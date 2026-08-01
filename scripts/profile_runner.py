"""Closed profile execution for source-bound merge-gate v1 workflows."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

import yaml

NODE_VERSION = "22.14.0"
PESTER_VERSION = "5.7.1"
MANAGER_VERSIONS = {"npm": "10.9.2", "pnpm": "10.4.1", "yarn": "4.7.0"}
NODE_LOCKS = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
}
PROFILES = {"baseline", "python", "node", "powershell", "critical-ml"}
LANES = {"deterministic", "security", "coverage"}
PYTHON_PROFILES = {"python", "critical-ml"}
CRITICAL_CATEGORIES = {"leakage", "lineage", "model", "parity", "schema"}
PINNED_PYTHON_TOOLS = {
    "ruff==0.14.14",
    "mypy==1.19.1",
    "bandit==1.9.4",
    "pip-audit==2.10.0",
}
EXCLUDED_STRUCTURAL_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "venv",
}
Runner = Callable[..., str]


def _reject_nonregular_tracked_entries(root: Path) -> None:
    """Reject links, gitlinks, and unmerged entries before host-side target reads."""
    if not (root / ".git").exists():
        return
    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "--stage", "-z"],
            cwd=root,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("tracked-file inventory is unavailable") from error
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, _path = record.split(b"\t", 1)
            mode, _object_id, stage = metadata.split()
        except ValueError as error:
            raise ValueError("tracked-file inventory is malformed") from error
        if mode not in {b"100644", b"100755"} or stage != b"0":
            raise ValueError("target contains a non-regular or unmerged tracked entry")


def _regular_target_file(root: Path, relative: Path | str) -> Path:
    """Return one candidate file only when it is a bounded regular non-link."""
    root = root.resolve()
    candidate = root / relative
    try:
        candidate.relative_to(root)
        metadata = candidate.lstat()
    except (OSError, ValueError) as error:
        raise ValueError(f"candidate file is unavailable: {relative}") from error
    if not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink():
        raise ValueError(f"candidate file is not a regular non-symlink file: {relative}")
    resolved = candidate.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"candidate file escapes the target root: {relative}")
    return candidate


def _trusted_site() -> Path:
    """Resolve the site-packages root containing exact platform tool pins."""
    return Path(str(importlib.metadata.distribution("ruff").locate_file(""))).resolve()


def _python_module(platform_root: Path, module: str, *arguments: str) -> list[str]:
    """Invoke installed tooling with no site startup or target-controlled path."""
    launcher = platform_root / "scripts" / "run_module_isolated.py"
    if not launcher.is_file():
        raise ValueError("immutable isolated platform-tool launcher is missing")
    return [
        sys.executable,
        "-I",
        "-S",
        str(launcher),
        "--trusted-site",
        str(_trusted_site()),
        "--module",
        module,
        "--",
        *arguments,
    ]


def _node_configuration(root: Path) -> tuple[str, str]:
    package_path = root / "package.json"
    if not package_path.is_file():
        raise ValueError("Node profile requires package.json")
    try:
        package = json.loads(_regular_target_file(root, "package.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("Node profile package.json is malformed") from error
    if not isinstance(package, dict):
        raise ValueError("Node profile package.json is malformed")
    locks = [name for name in NODE_LOCKS if (root / name).is_file()]
    if len(locks) != 1:
        raise ValueError("Node profile requires exactly one supported lockfile")
    manager = NODE_LOCKS[locks[0]]
    declared = package.get("packageManager")
    expected = f"{manager}@{MANAGER_VERSIONS[manager]}"
    if declared != expected:
        raise ValueError(f"Node profile requires exact packageManager {expected}")
    return manager, expected


def _node_plan(root: Path, lane: str, *, platform_root: Path | None, base_sha: str | None) -> list[list[str]]:
    _node_configuration(root)
    if lane == "security":
        return []
    if lane != "deterministic":
        raise ValueError("Node coverage is explicitly not applicable")
    if platform_root is None or base_sha is None or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise ValueError("Node deterministic lane requires immutable platform and protected-base SHA")
    validator = platform_root / "scripts" / "validate_node_test_policy.py"
    if not validator.is_file():
        raise ValueError("immutable Node test-policy validator is missing")
    return [
        [
            sys.executable,
            "-I",
            str(validator),
            "--root",
            str(root),
            "--base-sha",
            base_sha,
        ]
    ]


def _powershell_plan(root: Path, lane: str) -> list[list[str]]:
    if lane != "deterministic":
        raise ValueError(f"PowerShell {lane} is explicitly not applicable")
    if not list(root.glob("tests/**/*.Tests.ps1")):
        raise ValueError("PowerShell profile requires a Pester *.Tests.ps1 file")
    return []


def _validate_python_platform(root: Path, platform_root: Path) -> None:
    if not (root / "requirements.txt").is_file() and not (root / "pyproject.toml").is_file():
        raise ValueError("Python profile requires requirements.txt or pyproject.toml")
    tools = platform_root / "requirements-dev.txt"
    if not tools.is_file():
        raise ValueError("immutable platform requirements-dev.txt is missing")
    pinned_lines = {
        line.strip()
        for line in tools.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    if not pinned_lines >= PINNED_PYTHON_TOOLS:
        raise ValueError("immutable platform Python tool pins are incomplete or drifted")
    for requirement in PINNED_PYTHON_TOOLS:
        distribution, expected = requirement.split("==", 1)
        if importlib.metadata.version(distribution) != expected:
            raise ValueError(f"trusted platform tool version drifted: {distribution}")
    for relative in ("contract/bandit-v1.ini", "contract/ruff-v1.toml", "contract/mypy-v1.ini"):
        if not (platform_root / relative).is_file():
            raise ValueError(f"immutable Python static config is missing: {relative}")


def _common_security_plan(root: Path, platform_root: Path | None) -> list[list[str]]:
    if platform_root is None:
        raise ValueError("security lane requires immutable platform_root")
    contract_path = platform_root / "contract" / "v1.json"
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        security = contract["x-merge-gate-v1"]["common_security"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("common secret-scan contract is unavailable") from error
    expected = {
        "tool": "scripts/secret_scan.py",
        "tool_version": "1.0.0",
        "config": "contract/secret-scan-v1.json",
        "status": "required-all-profiles",
        "target_scope": "git-tracked-files",
        "target_code_execution": False,
    }
    if not isinstance(security, dict) or any(security.get(key) != value for key, value in expected.items()):
        raise ValueError("common secret-scan contract is invalid")
    digest = security.get("config_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("common secret-scan config digest is invalid")
    scanner = platform_root / security["tool"]
    config = platform_root / security["config"]
    if not scanner.is_file() or not config.is_file():
        raise ValueError("common secret-scan tool or config is missing")
    return [
        [
            sys.executable,
            str(scanner),
            "--root",
            str(root),
            "--config",
            str(config),
            "--expected-config-sha256",
            digest,
        ]
    ]


def _critical_policy(root: Path) -> None:
    path = root / ".github" / "ci-platform-test-policy.json"
    try:
        policy = json.loads(_regular_target_file(root, Path(".github") / path.name).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("critical-ml requires a valid ci-platform-test-policy.json") from error
    critical = policy.get("critical_tests") if isinstance(policy, dict) else None
    if (
        not isinstance(critical, dict)
        or set(critical) != CRITICAL_CATEGORIES
        or any(
            not isinstance(paths, list)
            or not paths
            or any(not isinstance(path_value, str) or not path_value for path_value in paths)
            for paths in critical.values()
        )
    ):
        raise ValueError("critical-ml requires leakage/lineage/model/parity/schema protected hooks")


def _python_plan(
    profile: str,
    root: Path,
    lane: str,
    *,
    platform_root: Path | None,
    base_sha: str | None,
    head_sha: str | None,
    evidence_dir: Path | None,
    target_site: Path | None,
) -> list[list[str]]:
    if platform_root is None:
        raise ValueError("Python profile requires immutable platform_root")
    _validate_python_platform(root, platform_root)
    commands: list[list[str]] = []
    if lane == "deterministic":
        ruff_config = platform_root / "contract" / "ruff-v1.toml"
        commands.extend(
            (
                _python_module(platform_root, "ruff", "check", "--config", str(ruff_config), "."),
                _python_module(
                    platform_root,
                    "ruff",
                    "format",
                    "--check",
                    "--config",
                    str(ruff_config),
                    ".",
                ),
            )
        )
        if profile == "critical-ml":
            _critical_policy(root)
            if base_sha is None or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
                raise ValueError("critical-ml deterministic lane requires protected-base SHA")
            validate_policy = platform_root / "scripts" / "validate_test_policy_manifest.py"
            if not validate_policy.is_file():
                raise ValueError("immutable platform test-policy manifest validator is missing")
            commands.append(
                [
                    sys.executable,
                    str(validate_policy),
                    "--base-sha",
                    base_sha,
                    "--profile",
                    profile,
                ]
            )
        return commands
    if lane == "security":
        bandit_config = platform_root / "contract" / "bandit-v1.ini"
        commands.append(
            _python_module(
                platform_root,
                "bandit",
                "--ini",
                str(bandit_config),
                "-r",
                ".",
                "-x",
                "tests,.venv,venv",
            )
        )
        return commands
    if lane != "coverage":
        raise ValueError(f"unsupported Python lane: {lane}")
    if (
        base_sha is None
        or head_sha is None
        or not re.fullmatch(r"[0-9a-f]{40}", base_sha)
        or not re.fullmatch(r"[0-9a-f]{40}", head_sha)
        or evidence_dir is None
        or target_site is None
    ):
        raise ValueError("coverage requires exact base/head SHAs, evidence_dir, and isolated target_site")
    run_policy = platform_root / "scripts" / "run_test_policy.py"
    if not run_policy.is_file():
        raise ValueError("immutable platform test-policy runner is missing")
    coverage_xml = evidence_dir / "coverage.xml"
    coverage_json = evidence_dir / "coverage.json"
    commands.extend(
        (
            [
                sys.executable,
                str(run_policy),
                "--base-sha",
                base_sha,
                "--profile",
                profile,
                "--evidence-dir",
                str(evidence_dir),
                "--coverage-xml",
                str(coverage_xml),
                "--coverage-json",
                str(coverage_json),
                "--trusted-site",
                str(_trusted_site()),
                "--target-site",
                str(target_site),
            ],
        )
    )
    return commands


def plan(
    profile: str,
    root: Path,
    *,
    lane: str = "deterministic",
    platform_root: Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    evidence_dir: Path | None = None,
    target_site: Path | None = None,
) -> list[list[str]]:
    """Return a fixed command plan; repository text never becomes a shell command."""
    if profile not in PROFILES:
        raise ValueError(f"unsupported profile: {profile}")
    if lane not in LANES:
        raise ValueError(f"unsupported lane: {lane}")
    common_security = _common_security_plan(root, platform_root) if lane == "security" else []
    if profile == "node":
        return common_security + _node_plan(root, lane, platform_root=platform_root, base_sha=base_sha)
    if profile == "powershell":
        if lane == "security":
            return common_security
        return _powershell_plan(root, lane)
    if profile in PYTHON_PROFILES:
        return common_security + _python_plan(
            profile,
            root,
            lane,
            platform_root=platform_root,
            base_sha=base_sha,
            head_sha=head_sha,
            evidence_dir=evidence_dir,
            target_site=target_site,
        )
    if lane == "security":
        return common_security
    if lane != "deterministic":
        raise ValueError(f"baseline {lane} is explicitly not applicable")
    return []


def _subprocess_runner(command: list[str], *, cwd: Path, capture_output: bool) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        timeout=3600,
        capture_output=capture_output,
        text=True,
    )
    return result.stdout if capture_output else ""


def _version(value: str) -> str:
    return value.strip().removeprefix("v")


def _validate_structured_files(root: Path) -> None:
    seen = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("baseline contains a symbolic link")
        if not path.is_file() or EXCLUDED_STRUCTURAL_PARTS.intersection(path.relative_to(root).parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in {".json", ".toml", ".yaml", ".yml"}:
            continue
        seen += 1
        try:
            text = path.read_text(encoding="utf-8")
            if suffix == ".json":
                json.loads(text)
            elif suffix == ".toml":
                tomllib.loads(text)
            else:
                yaml.safe_load(text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as error:
            raise ValueError(f"malformed structured data: {path.relative_to(root)}") from error
    if seen == 0:
        raise ValueError("baseline requires at least one JSON, TOML, or YAML file")


def execute(
    profile: str,
    root: Path,
    *,
    lane: str = "deterministic",
    platform_root: Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    evidence_dir: Path | None = None,
    target_site: Path | None = None,
    runner: Runner | None = None,
) -> None:
    """Execute one closed profile lane after validating its prerequisites."""
    _reject_nonregular_tracked_entries(root)
    if profile == "baseline" and lane == "deterministic":
        if lane != "deterministic":
            raise ValueError(f"baseline {lane} is explicitly not applicable")
        _validate_structured_files(root)
        return

    run = runner or _subprocess_runner
    commands = plan(
        profile,
        root,
        lane=lane,
        platform_root=platform_root,
        base_sha=base_sha,
        head_sha=head_sha,
        evidence_dir=evidence_dir,
        target_site=target_site,
    )
    if profile == "node":
        if lane in {"deterministic", "security"}:
            for command in commands:
                run(command, cwd=root, capture_output=False)
            return
        manager, _ = _node_configuration(root)
        node_version = _version(run(["node", "--version"], cwd=root, capture_output=True))
        if node_version != NODE_VERSION:
            raise ValueError(f"installed node version {node_version!r} does not match {NODE_VERSION}")
        common_count = 1 if lane == "security" else 0
        for command in commands[:common_count]:
            run(command, cwd=root, capture_output=False)
        remaining = commands[common_count:]
        setup_count = 2 if manager in {"pnpm", "yarn"} else 0
        for command in remaining[:setup_count]:
            run(command, cwd=root, capture_output=False)
        remaining = remaining[setup_count:]
        manager_version = _version(run([manager, "--version"], cwd=root, capture_output=True))
        if manager_version != MANAGER_VERSIONS[manager]:
            raise ValueError(
                f"installed {manager} version {manager_version!r} does not match {MANAGER_VERSIONS[manager]}"
            )
        for command in remaining:
            run(command, cwd=root, capture_output=False)
        return

    if profile == "powershell" and lane == "deterministic":
        return

    if evidence_dir is not None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
    for command in commands:
        run(command, cwd=root, capture_output=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true", required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--lane", choices=sorted(LANES), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--platform-root", type=Path)
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--target-site", type=Path)
    args = parser.parse_args()
    execute(
        args.profile,
        args.root,
        lane=args.lane,
        platform_root=args.platform_root,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        evidence_dir=args.evidence_dir,
        target_site=args.target_site,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
