"""Evaluate global, patch, critical-patch, and path-group coverage floors."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
from collections.abc import Mapping
from typing import Any, NamedTuple

import yaml

DEFAULT_CRITICAL_PATHS: tuple[str, ...] = (
    "src/features/",
    "src/inference/",
    "src/training/",
    "src/validation/",
    "leakage",
    "lineage",
    "schema",
    "model_registry",
    "prediction",
)


class PathGroupPolicy(NamedTuple):
    floor: float
    target: float


class CoveragePolicy(NamedTuple):
    global_floor: float
    diff_floor: float
    critical_patch_floor: float
    critical_paths: tuple[str, ...]
    path_groups: dict[str, PathGroupPolicy]


def _percentage(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a numeric percentage")
    parsed = float(value)
    if not 0 <= parsed <= 100:
        raise ValueError(f"{field} must be between 0 and 100")
    return parsed


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./").strip("/")


def _coverage_policy(value: Any) -> CoveragePolicy:
    coverage: Mapping[str, Any] = {}
    if value is not None:
        if not isinstance(value, Mapping):
            raise ValueError("quality-debt registry must be a mapping")
        configured = value.get("coverage")
        if not isinstance(configured, Mapping):
            raise ValueError("quality-debt registry has no coverage mapping")
        coverage = configured

    global_floor = _percentage(
        coverage.get("global_floor", 50),
        "coverage.global_floor",
    )
    diff_floor = _percentage(
        coverage.get("diff_floor", 95),
        "coverage.diff_floor",
    )
    critical_floor = 95.0
    critical_paths = DEFAULT_CRITICAL_PATHS
    if "critical_patch" in coverage:
        critical = coverage["critical_patch"]
        if not isinstance(critical, Mapping):
            raise ValueError("coverage.critical_patch must be a mapping")
        critical_floor = _percentage(
            critical.get("target"),
            "coverage.critical_patch.target",
        )
        paths = critical.get("paths")
        if (
            not isinstance(paths, list)
            or not paths
            or any(not isinstance(item, str) or not item.strip() for item in paths)
        ):
            raise ValueError("coverage.critical_patch.paths must be a non-empty string list")
        critical_paths = tuple(_normalise_path(item) for item in paths)

    path_groups: dict[str, PathGroupPolicy] = {}
    configured_groups = coverage.get("path_groups", {})
    if not isinstance(configured_groups, Mapping):
        raise ValueError("coverage.path_groups must be a mapping")
    for raw_prefix, config in configured_groups.items():
        if not isinstance(raw_prefix, str) or not raw_prefix.strip():
            raise ValueError("coverage.path_groups keys must be non-empty strings")
        if not isinstance(config, Mapping):
            raise ValueError(f"coverage.path_groups.{raw_prefix} must be a mapping")
        floor = _percentage(
            config.get("floor"),
            f"coverage.path_groups.{raw_prefix}.floor",
        )
        target = _percentage(
            config.get("target", 85),
            f"coverage.path_groups.{raw_prefix}.target",
        )
        if floor > target:
            raise ValueError(f"coverage.path_groups.{raw_prefix}.floor exceeds target")
        path_groups[_normalise_path(raw_prefix)] = PathGroupPolicy(floor, target)

    return CoveragePolicy(
        global_floor=global_floor,
        diff_floor=diff_floor,
        critical_patch_floor=critical_floor,
        critical_paths=critical_paths,
        path_groups=path_groups,
    )


def load_policy_bytes(raw: bytes) -> CoveragePolicy:
    if not raw:
        raise ValueError("quality-debt registry is empty")
    try:
        decoded = raw.decode("utf-8")
        value = yaml.safe_load(decoded)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("quality-debt registry is not valid UTF-8 YAML") from error
    return _coverage_policy(value)


def load_policy(path: pathlib.Path | None) -> CoveragePolicy:
    if path is None or not path.is_file():
        return _coverage_policy(None)
    return load_policy_bytes(path.read_bytes())


def load_policy_from_base(
    root: pathlib.Path,
    base_sha: str,
) -> CoveragePolicy:
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise ValueError("protected-base SHA is malformed")
    result = subprocess.run(
        ["git", "show", f"{base_sha}:quality_debt.yml"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        return load_policy_bytes(result.stdout)
    subprocess.run(
        ["git", "cat-file", "-e", f"{base_sha}^{{commit}}"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return _coverage_policy(None)


def _matches(path: str, marker: str) -> bool:
    normal_path = _normalise_path(path)
    normal_marker = _normalise_path(marker)
    return (
        normal_path == normal_marker
        or normal_path.startswith(f"{normal_marker}/")
        or ("/" not in normal_marker and normal_marker.lower() in normal_path.lower())
    )


def _entry_lines(
    entry: Mapping[str, Any],
    path: str,
) -> tuple[set[int], set[int], set[int]]:
    executed = entry.get("executed_lines")
    missing = entry.get("missing_lines")
    excluded = entry.get("excluded_lines")
    if (
        not isinstance(executed, list)
        or not isinstance(missing, list)
        or not isinstance(excluded, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in executed)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in missing)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in excluded)
    ):
        raise ValueError(f"coverage entry has malformed line metadata: {path}")
    line_sets = (set(executed), set(missing), set(excluded))
    if (
        any(item < 1 for values in line_sets for item in values)
        or any(len(values) != len(raw) for values, raw in zip(line_sets, (executed, missing, excluded), strict=True))
        or line_sets[0] & line_sets[1]
        or line_sets[0] & line_sets[2]
        or line_sets[1] & line_sets[2]
    ):
        raise ValueError(f"coverage entry has inconsistent line metadata: {path}")
    return line_sets


def _entry_summary(entry: Mapping[str, Any], path: str) -> tuple[int, int]:
    summary = entry.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError(f"coverage entry has no summary: {path}")
    covered = summary.get("covered_lines")
    total = summary.get("num_statements")
    if (
        isinstance(covered, bool)
        or not isinstance(covered, int)
        or isinstance(total, bool)
        or not isinstance(total, int)
        or covered < 0
        or total < 0
        or covered > total
    ):
        raise ValueError(f"coverage entry has malformed summary: {path}")
    return covered, total


def evaluate_report(
    report: Mapping[str, Any],
    *,
    changed_lines: Mapping[str, set[int]],
    existing_python_paths: set[str],
    policy: CoveragePolicy,
) -> dict[str, Any]:
    totals = report.get("totals")
    files = report.get("files")
    if not isinstance(totals, Mapping) or not isinstance(files, Mapping):
        raise ValueError("coverage report has no totals/files mapping")
    global_coverage = _percentage(
        totals.get("percent_covered"),
        "coverage report global percentage",
    )
    if global_coverage + 1e-9 < policy.global_floor:
        raise ValueError(f"global coverage {global_coverage:.2f} is below floor {policy.global_floor:.2f}")

    normal_files: dict[str, Mapping[str, Any]] = {}
    for raw_path, entry in files.items():
        if not isinstance(raw_path, str) or not isinstance(entry, Mapping):
            raise ValueError("coverage report contains malformed file metadata")
        path = _normalise_path(raw_path)
        if path in normal_files:
            raise ValueError(f"coverage report contains duplicate path: {path}")
        normal_files[path] = entry

    existing = {_normalise_path(path) for path in existing_python_paths}
    changed = {
        _normalise_path(path): lines for path, lines in changed_lines.items() if _normalise_path(path).endswith(".py")
    }
    diff_hit = diff_total = critical_hit = critical_total = 0
    excluded_changed_total = 0
    touched_critical = False
    for path, lines in changed.items():
        if path not in existing:
            continue
        entry = normal_files.get(path)
        if entry is None:
            raise ValueError(f"changed Python file is absent from coverage report: {path}")
        executed, missing, excluded = _entry_lines(entry, path)
        excluded_changed = set(lines) & excluded
        excluded_changed_total += len(excluded_changed)
        if excluded_changed:
            sample = ",".join(str(line) for line in sorted(excluded_changed)[:20])
            raise ValueError(f"coverage report contains excluded changed lines: {path}:{sample}")
        measurable = set(lines) & (executed | missing)
        diff_hit += len(measurable & executed)
        diff_total += len(measurable)
        if any(_matches(path, marker) for marker in policy.critical_paths):
            touched_critical = True
            critical_hit += len(measurable & executed)
            critical_total += len(measurable)

    diff_coverage = 100.0 if diff_total == 0 else diff_hit * 100.0 / diff_total
    critical_coverage = 100.0 if critical_total == 0 else critical_hit * 100.0 / critical_total
    if diff_coverage + 1e-9 < policy.diff_floor:
        raise ValueError(f"diff coverage {diff_coverage:.2f} is below floor {policy.diff_floor:.2f}")
    if touched_critical and critical_coverage + 1e-9 < policy.critical_patch_floor:
        raise ValueError(
            f"critical patch coverage {critical_coverage:.2f} is below floor {policy.critical_patch_floor:.2f}"
        )

    group_results: dict[str, dict[str, float | int]] = {}
    for prefix, group in policy.path_groups.items():
        covered = total = 0
        matched = False
        for path, entry in normal_files.items():
            if not _matches(path, prefix):
                continue
            matched = True
            file_covered, file_total = _entry_summary(entry, path)
            covered += file_covered
            total += file_total
        if not matched or total == 0:
            raise ValueError(f"path group has no measured statements: {prefix}")
        percent = covered * 100.0 / total
        if percent + 1e-9 < group.floor:
            raise ValueError(f"path-group coverage {prefix} {percent:.2f} is below floor {group.floor:.2f}")
        group_results[prefix] = {
            "coverage": percent,
            "covered_lines": covered,
            "floor": group.floor,
            "target": group.target,
            "total_lines": total,
        }

    return {
        "critical_patch_coverage": critical_coverage,
        "critical_patch_coverage_floor": policy.critical_patch_floor,
        "diff_coverage": diff_coverage,
        "diff_coverage_floor": policy.diff_floor,
        "excluded_changed_lines": excluded_changed_total,
        "global_coverage": global_coverage,
        "global_coverage_floor": policy.global_floor,
        "path_groups": group_results,
        "status": "passed",
    }


def changed_python_lines(base_sha: str, head_sha: str) -> dict[str, set[int]]:
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("base/head SHA is malformed")
    diff = subprocess.check_output(
        [
            "git",
            "diff",
            "--unified=0",
            "--no-ext-diff",
            f"{base_sha}...{head_sha}",
            "--",
            "*.py",
        ],
        text=True,
    )
    changed: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = _normalise_path(line[6:])
            changed.setdefault(current, set())
        elif current and line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                start = int(match.group(1))
                count = int(match.group(2) or "1")
                changed[current].update(range(start, start + count))
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-json", type=pathlib.Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument(
        "--profile",
        choices=("baseline", "python", "node", "powershell", "critical-ml"),
        required=True,
    )
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    report = json.loads(arguments.coverage_json.read_text(encoding="utf-8"))
    if not isinstance(report, Mapping):
        raise ValueError("coverage JSON root must be a mapping")
    changed = changed_python_lines(arguments.base_sha, arguments.head_sha)
    existing = {path for path in changed if pathlib.Path(path).is_file() and path.endswith(".py")}
    policy = load_policy_from_base(pathlib.Path.cwd(), arguments.base_sha)
    if arguments.profile == "baseline":
        summary = {
            "applicability": "not-applicable",
            "critical_patch_coverage": 100.0,
            "critical_patch_coverage_floor": policy.critical_patch_floor,
            "diff_coverage": 100.0,
            "diff_coverage_floor": policy.diff_floor,
            "global_coverage": 100.0,
            "global_coverage_floor": policy.global_floor,
            "path_groups": {},
            "status": "passed",
        }
    else:
        summary = evaluate_report(
            report,
            changed_lines=changed,
            existing_python_paths=existing,
            policy=policy,
        )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
