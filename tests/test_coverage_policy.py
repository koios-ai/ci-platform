from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_coverage.py"


def load_module() -> ModuleType:
    assert SCRIPT.is_file()
    spec = importlib.util.spec_from_file_location("evaluate_coverage", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_and_generic_critical_policy_values_are_fail_closed(tmp_path: Path) -> None:
    module = load_module()
    defaults = module.load_policy(None)
    assert defaults.global_floor == 50
    assert defaults.diff_floor == 95
    assert defaults.critical_patch_floor == 95

    registry = tmp_path / "quality_debt.yml"
    registry.write_text(
        """
coverage:
  global_floor: 50
  diff_floor: 95
  critical_patch:
    target: 97
    paths: [src/critical_contract.py, src/training/]
  path_groups:
    src/training: {floor: 45, target: 85}
""",
        encoding="utf-8",
    )
    policy = module.load_policy(registry)
    assert policy.critical_patch_floor == 97
    assert policy.critical_paths == (
        "src/critical_contract.py",
        "src/training",
    )
    assert policy.path_groups["src/training"].floor == 45


def test_changed_python_file_missing_from_coverage_is_not_treated_as_100() -> None:
    module = load_module()
    report = {
        "totals": {"percent_covered": 99},
        "files": {},
    }
    with pytest.raises(ValueError, match="absent from coverage"):
        module.evaluate_report(
            report,
            changed_lines={"src/new_logic.py": {1, 2}},
            existing_python_paths={"src/new_logic.py"},
            policy=module.load_policy(None),
        )


def test_diff_critical_and_path_group_floors_are_semantic() -> None:
    module = load_module()
    report: dict[str, Any] = {
        "totals": {"percent_covered": 90},
        "files": {
            "src/training/model.py": {
                "executed_lines": [1, 2, 3],
                "missing_lines": [4],
                "excluded_lines": [],
                "summary": {"covered_lines": 3, "num_statements": 4},
            },
            "src/widget.py": {
                "executed_lines": [1, 2],
                "missing_lines": [],
                "excluded_lines": [],
                "summary": {"covered_lines": 2, "num_statements": 2},
            },
        },
    }
    policy = module.CoveragePolicy(
        global_floor=50,
        diff_floor=40,
        critical_patch_floor=80,
        critical_paths=("src/training/",),
        path_groups={"src/training": module.PathGroupPolicy(floor=70, target=85)},
    )
    with pytest.raises(ValueError, match="critical patch"):
        module.evaluate_report(
            report,
            changed_lines={"src/training/model.py": {1, 4}},
            existing_python_paths={"src/training/model.py"},
            policy=policy,
        )

    report["files"]["src/training/model.py"]["executed_lines"] = [1, 2, 3, 4]
    report["files"]["src/training/model.py"]["missing_lines"] = []
    report["files"]["src/training/model.py"]["summary"] = {
        "covered_lines": 4,
        "num_statements": 4,
    }
    summary = module.evaluate_report(
        report,
        changed_lines={"src/training/model.py": {1, 4}},
        existing_python_paths={"src/training/model.py"},
        policy=policy,
    )
    assert summary["diff_coverage"] == 100
    assert summary["critical_patch_coverage"] == 100
    assert summary["path_groups"]["src/training"]["coverage"] == 100


def test_changed_excluded_executable_line_is_never_treated_as_covered() -> None:
    module = load_module()
    report = {
        "totals": {"percent_covered": 100},
        "files": {
            "src/training/model.py": {
                "executed_lines": [1],
                "missing_lines": [],
                "excluded_lines": [2],
                "summary": {"covered_lines": 1, "num_statements": 1},
            }
        },
    }
    with pytest.raises(ValueError, match="excluded changed lines"):
        module.evaluate_report(
            report,
            changed_lines={"src/training/model.py": {2}},
            existing_python_paths={"src/training/model.py"},
            policy=module.load_policy(None),
        )


def test_changed_non_statement_line_does_not_inflate_patch_denominator() -> None:
    module = load_module()
    report = {
        "totals": {"percent_covered": 100},
        "files": {
            "src/widget.py": {
                "executed_lines": [1],
                "missing_lines": [],
                "excluded_lines": [],
                "summary": {"covered_lines": 1, "num_statements": 1},
            }
        },
    }
    summary = module.evaluate_report(
        report,
        changed_lines={"src/widget.py": {2}},
        existing_python_paths={"src/widget.py"},
        policy=module.load_policy(None),
    )
    assert summary["diff_coverage"] == 100
    assert summary["excluded_changed_lines"] == 0


def test_malformed_critical_and_path_group_policy_is_rejected(
    tmp_path: Path,
) -> None:
    module = load_module()
    for index, body in enumerate(
        (
            "coverage: {global_floor: 50, diff_floor: 95, critical_patch: nope}",
            """
coverage:
  global_floor: 50
  diff_floor: 95
  critical_patch: {target: 95, paths: []}
""",
            """
coverage:
  global_floor: 50
  diff_floor: 95
  path_groups: {src/training: {floor: 101}}
""",
        )
    ):
        path = tmp_path / f"invalid-{index}.yml"
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ValueError):
            module.load_policy(path)


def test_summary_is_json_serializable() -> None:
    module = load_module()
    report = {
        "totals": {"percent_covered": 100},
        "files": {
            "src/widget.py": {
                "executed_lines": [1],
                "missing_lines": [],
                "excluded_lines": [],
                "summary": {"covered_lines": 1, "num_statements": 1},
            }
        },
    }
    summary = module.evaluate_report(
        report,
        changed_lines={"src/widget.py": {1}},
        existing_python_paths={"src/widget.py"},
        policy=module.load_policy(None),
    )
    assert json.loads(json.dumps(summary))["status"] == "passed"
