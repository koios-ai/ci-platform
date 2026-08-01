"""Execute the closed deterministic-quality replacement canaries."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PRODUCTION_STATIC_POLICY = {
    "ruff": {
        "command": "python -m ruff check --config contract/ruff-v1.toml",
        "config": "contract/ruff-v1.toml",
    },
    "strict-mypy": {
        "command": "python -m mypy --config-file contract/mypy-v1.ini",
        "config": "contract/mypy-v1.ini",
    },
}


def command_for_batch(
    records: list[tuple[str, dict[str, Any], Path]],
    cache_dir: Path,
    root: Path,
) -> list[str]:
    if not records:
        raise ValueError("quality canary batch is empty")
    tool = records[0][1]["tool"]
    policy = PRODUCTION_STATIC_POLICY.get(tool)
    if policy is None:
        raise ValueError(f"unapproved executable quality owner: {tool}")
    for _, owner, _ in records:
        if (
            owner.get("tool") != tool
            or owner.get("command") != policy["command"]
            or owner.get("config") != policy["config"]
        ):
            raise ValueError(f"quality owner {tool} is not bound to its production command and config")
    config = (root / policy["config"]).resolve()
    if root.resolve() not in config.parents or not config.is_file():
        raise ValueError(f"quality owner {tool} production config is unavailable: {policy['config']}")
    fixtures = [str(fixture) for _, _, fixture in records]
    if tool == "ruff":
        rules = sorted({str(owner["rule"]) for _, owner, _ in records})
        return [
            sys.executable,
            "-I",
            "-m",
            "ruff",
            "check",
            "--config",
            str(config),
            "--no-cache",
            "--select",
            ",".join(rules),
            *fixtures,
        ]
    if tool == "strict-mypy":
        return [
            sys.executable,
            "-I",
            "-m",
            "mypy",
            "--config-file",
            str(config),
            "--cache-dir",
            str(cache_dir),
            *fixtures,
        ]
    raise AssertionError("closed production static policy is incomplete")


def diagnostic_token(owner: dict[str, Any]) -> str:
    rule = owner["rule"]
    return rule if owner["tool"] == "ruff" else f"[{rule}]"


def fixture_has_diagnostic(
    output: str,
    *,
    fixture: Path,
    root: Path,
    diagnostic: str,
    tool: str,
) -> bool:
    normalized = output.replace("\\", "/").casefold()
    resolved_root = root.resolve()
    aliases = {
        fixture.resolve().as_posix().casefold(),
        fixture.resolve().relative_to(resolved_root).as_posix().casefold(),
    }
    records = normalized.splitlines() if tool == "strict-mypy" else re.split(r"\n\s*\n", normalized)
    token = diagnostic.casefold()
    return any(token in record and any(alias in record for alias in aliases) for record in records)


def run(
    root: Path,
    map_path: Path,
    *,
    version_resolver: Any = importlib.metadata.version,
) -> dict[str, list[str]]:
    quality = json.loads(map_path.read_text(encoding="utf-8"))
    if quality.get("schema_version") != 2:
        raise ValueError("quality map schema version must be 2")
    classes = quality.get("classes")
    if not isinstance(classes, dict) or len(classes) != 9:
        raise ValueError("quality map must contain exactly nine classes")
    executed: list[str] = []
    verified_versions: set[tuple[str, str]] = set()
    batches: dict[tuple[str, str], list[tuple[str, dict[str, Any], Path]]] = {}
    for name, entry in classes.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("owner"), dict):
            raise ValueError(f"quality class {name} is malformed")
        owner = entry["owner"]
        package = owner.get("package")
        pinned_version = owner.get("version")
        if not isinstance(package, str) or not isinstance(pinned_version, str):
            raise ValueError(f"quality class {name} has no pinned owner version")
        version_key = (package, pinned_version)
        if version_key not in verified_versions:
            installed_version = version_resolver(package)
            if installed_version != pinned_version:
                raise ValueError(f"installed {package} version {installed_version!r} does not match {pinned_version}")
            verified_versions.add(version_key)
        tool = owner.get("tool")
        if not isinstance(tool, str):
            raise ValueError(f"quality class {name} has no executable owner")
        for key in ("positive_canary", "negative_canary"):
            relative = entry.get(key)
            if not isinstance(relative, str):
                raise ValueError(f"quality class {name} lacks {key}")
            fixture = (root / relative).resolve()
            if root.resolve() not in fixture.parents or not fixture.is_file():
                raise ValueError(f"quality class {name} fixture is unavailable: {relative}")
            batches.setdefault((tool, key), []).append((name, owner, fixture))
        executed.append(name)

    with tempfile.TemporaryDirectory(prefix="koios-quality-canaries-") as temporary:
        for (tool, key), records in sorted(batches.items()):
            cache_dir = Path(temporary) / f"{tool}-{key}-cache"
            result = subprocess.run(
                command_for_batch(records, cache_dir, root),
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            positive = key == "positive_canary"
            if (result.returncode == 0) != positive:
                names = ", ".join(name for name, _, _ in records)
                raise ValueError(
                    f"quality canary batch {tool} {key} ({names}) did not produce the required result: "
                    f"{result.stdout}{result.stderr}"
                )
            output = f"{result.stdout}\n{result.stderr}"
            for name, owner, fixture in records:
                diagnostic = diagnostic_token(owner)
                observed = fixture_has_diagnostic(
                    output,
                    fixture=fixture,
                    root=root,
                    diagnostic=diagnostic,
                    tool=tool,
                )
                if not positive and not observed:
                    raise ValueError(
                        f"quality class {name} {key} lacks fixture-specific diagnostic {diagnostic}: {output}"
                    )
                if positive and observed:
                    raise ValueError(f"quality class {name} {key} unexpectedly emitted {diagnostic}")
    return {"executed": sorted(executed)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.root, args.map), sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
