"""Run closed, policy-selected repository-native final-gate hooks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from typing import Any

import yaml

SHA = re.compile(r"^[0-9a-f]{40}$")
CRITICAL_REQUIRED_PATHS = (
    "quality_debt.yml",
    "tools/check_docstring_contracts.py",
    "tools/check_data_quality_contract.py",
    "tools/check_schema_contract.py",
    "tools/check_rebuild_contract.py",
    "tools/check_module_coverage.py",
    "tools/check_coverage_ratchet.py",
)
DATA_QUALITY_COMMAND = ("tools/check_data_quality_contract.py", "--ci")


def load_registry_bytes(raw: bytes | None) -> dict[str, Any]:
    if raw is None:
        return {}
    try:
        decoded = raw.decode("utf-8")
        loaded = yaml.safe_load(decoded)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("quality-debt registry is not valid UTF-8 YAML") from error
    if not isinstance(loaded, dict):
        raise ValueError("quality-debt registry must be a mapping")
    return loaded


def load_registry(path: pathlib.Path) -> dict[str, Any]:
    return load_registry_bytes(path.read_bytes() if path.is_file() else None)


def load_registry_from_base(
    root: pathlib.Path,
    base_sha: str,
) -> tuple[dict[str, Any], bytes]:
    result = subprocess.run(
        ["git", "show", f"{base_sha}:quality_debt.yml"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return {}, b"absent\n"
    return load_registry_bytes(result.stdout), result.stdout


def required_hooks(
    profile: str,
    registry: Mapping[str, Any],
) -> set[str]:
    required: set[str] = set()
    if profile == "baseline":
        return required
    if "docstrings" in registry:
        required.add("docstrings")
    data_quality = registry.get("data_quality")
    if isinstance(data_quality, Mapping) and data_quality.get("pull_request_fixture_required") is True:
        required.add("data-quality")
    coverage = registry.get("coverage")
    if isinstance(coverage, Mapping):
        if coverage.get("path_groups"):
            required.add("path-group-coverage")
        if "critical_patch" in coverage or "diff_floor" in coverage:
            required.add("coverage-ratchet")
    if profile == "critical-ml":
        required.update(
            {
                "column-signatures",
                "rebuild-smoke",
                "docstrings",
                "data-quality",
                "path-group-coverage",
                "coverage-ratchet",
            }
        )
    return required


def validate_required_files(root: pathlib.Path, profile: str) -> None:
    if profile != "critical-ml":
        return
    missing = [relative for relative in CRITICAL_REQUIRED_PATHS if not (root / relative).is_file()]
    if missing:
        raise ValueError("critical-ml repository lacks required native hooks: " + ", ".join(missing))


def _run(
    command: list[str],
    *,
    cwd: pathlib.Path,
    timeout: int = 1800,
) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=timeout)


def _run_docstring_ratchet(
    root: pathlib.Path,
    *,
    base_sha: str,
    evidence_dir: pathlib.Path,
) -> None:
    changed_files = evidence_dir / "docstring-changed-files.txt"
    with changed_files.open("wb") as output:
        subprocess.run(
            [
                "git",
                "diff",
                "--name-status",
                "--find-renames",
                "--diff-filter=ACMRTU",
                f"{base_sha}...HEAD",
                "--",
                "*.py",
            ],
            cwd=root,
            check=True,
            stdout=output,
        )
    runner_temp = pathlib.Path(os.environ.get("RUNNER_TEMP", evidence_dir))
    runner_temp.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ci-platform-docstrings-",
        dir=runner_temp,
    ) as directory:
        base_root = pathlib.Path(directory) / "base"
        _run(
            ["git", "worktree", "add", "--detach", str(base_root), base_sha],
            cwd=root,
        )
        try:
            base_tool = base_root / "tools" / "check_docstring_contracts.py"
            base_registry = base_root / "quality_debt.yml"
            if not base_tool.is_file() or not base_registry.is_file():
                raise ValueError("base commit lacks docstring policy implementation")
            base_report = evidence_dir / "docstring-base-report.json"
            _run(
                [
                    sys.executable,
                    str(base_tool),
                    "--root",
                    str(base_root),
                    "--registry",
                    str(base_registry),
                    "--report-only",
                    "--summary-json",
                    str(base_report),
                ],
                cwd=base_root,
            )
            _run(
                [
                    sys.executable,
                    "tools/check_docstring_contracts.py",
                    "--registry",
                    str(base_registry),
                    "--base-report",
                    str(base_report),
                    "--changed-files",
                    str(changed_files),
                    "--summary-json",
                    str(evidence_dir / "docstring-quality-report.json"),
                ],
                cwd=root,
            )
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(base_root)],
                cwd=root,
                check=False,
                timeout=120,
            )
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=root,
                check=False,
                timeout=120,
            )


def _run_pre_test(
    root: pathlib.Path,
    *,
    profile: str,
    base_sha: str,
    registry: Mapping[str, Any],
    evidence_dir: pathlib.Path,
) -> list[str]:
    selected = required_hooks(profile, registry)
    executed: list[str] = []
    if "docstrings" in selected:
        _run_docstring_ratchet(
            root,
            base_sha=base_sha,
            evidence_dir=evidence_dir,
        )
        executed.append("docstrings")
    if "data-quality" in selected:
        _run([sys.executable, *DATA_QUALITY_COMMAND], cwd=root)
        executed.append("data-quality")
    if "column-signatures" in selected:
        output = evidence_dir / "column-signatures.json"
        _run(
            [
                sys.executable,
                "tools/check_schema_contract.py",
                "--output",
                str(output),
            ],
            cwd=root,
        )
        if not output.is_file():
            raise RuntimeError("column-signature hook produced no evidence")
        executed.append("column-signatures")
    if "rebuild-smoke" in selected:
        _run(
            [sys.executable, "tools/check_rebuild_contract.py"],
            cwd=root,
        )
        executed.append("rebuild-smoke")
    return executed


def _percentage(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    parsed = float(value)
    if not 0 <= parsed <= 100:
        raise ValueError(f"{field} is outside 0..100")
    return parsed


def _run_post_coverage(
    root: pathlib.Path,
    *,
    profile: str,
    base_sha: str,
    registry: Mapping[str, Any],
    registry_path: pathlib.Path,
    coverage_xml: pathlib.Path,
    evidence_dir: pathlib.Path,
) -> list[str]:
    if profile == "baseline":
        return []
    if not coverage_xml.is_file():
        raise ValueError("coverage XML is absent")
    selected = required_hooks(profile, registry)
    executed: list[str] = []
    normalizer = root / "tools" / "normalize_coverage_paths.py"
    if normalizer.is_file():
        _run(
            [sys.executable, str(normalizer), str(coverage_xml)],
            cwd=root,
        )
        executed.append("normalize-coverage")
    if "path-group-coverage" in selected:
        _run(
            [
                sys.executable,
                "tools/check_module_coverage.py",
                str(coverage_xml),
                "--registry",
                str(registry_path),
            ],
            cwd=root,
        )
        executed.append("path-group-coverage")
    if "coverage-ratchet" in selected:
        coverage = registry.get("coverage")
        if not isinstance(coverage, Mapping):
            raise ValueError("coverage policy is missing")
        diff_floor = _percentage(
            coverage.get("diff_floor", 95),
            "coverage.diff_floor",
        )
        diff_report = evidence_dir / "diff-cover.json"
        _run(
            [
                "diff-cover",
                str(coverage_xml),
                f"--compare-branch={base_sha}",
                f"--fail-under={diff_floor:g}",
                "--format",
                f"json:{diff_report}",
            ],
            cwd=root,
        )
        if not diff_report.is_file():
            raise RuntimeError("diff-cover produced no JSON evidence")
        _run(
            [
                sys.executable,
                "tools/check_coverage_ratchet.py",
                str(coverage_xml),
                "--registry",
                str(registry_path),
                "--diff-cover-json",
                str(diff_report),
            ],
            cwd=root,
        )
        executed.append("coverage-ratchet")
    return executed


def run_hooks(
    *,
    root: pathlib.Path,
    phase: str,
    profile: str,
    base_sha: str,
    coverage_xml: pathlib.Path | None,
    output: pathlib.Path,
) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("repository root is unavailable")
    if profile not in {"baseline", "python", "node", "powershell", "critical-ml"}:
        raise ValueError("profile is invalid")
    if phase not in {"pre-test", "post-coverage"}:
        raise ValueError("repository-hook phase is invalid")
    if not SHA.fullmatch(base_sha):
        raise ValueError("base SHA is malformed")
    registry, registry_raw = load_registry_from_base(root, base_sha)
    validate_required_files(root, profile)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    native_evidence_digests: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="ci-platform-policy-") as directory:
        working_evidence = pathlib.Path(directory)
        registry_path = working_evidence / "quality_debt.yml"
        registry_path.write_bytes(registry_raw)
        if phase == "pre-test":
            executed = _run_pre_test(
                root,
                profile=profile,
                base_sha=base_sha,
                registry=registry,
                evidence_dir=working_evidence,
            )
        else:
            if coverage_xml is None:
                raise ValueError("post-coverage phase lacks coverage XML")
            executed = _run_post_coverage(
                root,
                profile=profile,
                base_sha=base_sha,
                registry=registry,
                registry_path=registry_path,
                coverage_xml=coverage_xml.resolve(),
                evidence_dir=working_evidence,
            )
        native_evidence_digests = {
            path.relative_to(working_evidence).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(working_evidence.rglob("*"))
            if path.is_file() and path != registry_path
        }
    summary = {
        "base_sha": base_sha,
        "executed": executed,
        "native_evidence_digests": native_evidence_digests,
        "phase": phase,
        "profile": profile,
        "protected_quality_debt_digest": hashlib.sha256(registry_raw).hexdigest(),
        "required": sorted(required_hooks(profile, registry)),
        "status": "passed",
    }
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase",
        choices=("pre-test", "post-coverage"),
        required=True,
    )
    parser.add_argument(
        "--profile",
        choices=("baseline", "python", "node", "powershell", "critical-ml"),
        required=True,
    )
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--coverage-xml", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    run_hooks(
        root=pathlib.Path.cwd(),
        phase=arguments.phase,
        profile=arguments.profile,
        base_sha=arguments.base_sha,
        coverage_xml=arguments.coverage_xml,
        output=arguments.output,
    )


if __name__ == "__main__":
    main()
