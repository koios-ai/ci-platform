from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy_non_regression.py"


def load_module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def sample_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "test_roots": ["tests"],
        "marker_exclusions": ["slow"],
        "registered_markers": ["slow"],
        "disabled_plugins": ["benchmark"],
        "coverage_sources": ["src"],
        "protected_support_files": ["tests/conftest.py"],
        "critical_tests": {
            "leakage": ["tests/test_leakage.py"],
            "lineage": ["tests/test_lineage.py"],
            "model": ["tests/test_model.py"],
            "parity": ["tests/test_parity.py"],
            "schema": ["tests/test_schema.py"],
        },
        "unexpected_skip_policy": "fail",
    }


def materialize(root: Path) -> None:
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "tests" / "conftest.py").write_text("# protected support\n", encoding="utf-8")
    for relative in (
        "tests/test_leakage.py",
        "tests/test_lineage.py",
        "tests/test_model.py",
        "tests/test_parity.py",
        "tests/test_schema.py",
        "tests/test_new_schema.py",
    ):
        (root / relative).write_text(
            "def test_placeholder():\n    assert True\n",
            encoding="utf-8",
        )


def policy_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def quality_bytes(
    *,
    global_floor: int = 50,
    diff_floor: int = 95,
    critical_floor: int = 95,
    critical_paths: str = "[src/training/]",
    group_floor: int = 45,
) -> bytes:
    return f"""\
coverage:
  global_floor: {global_floor}
  diff_floor: {diff_floor}
  critical_patch:
    target: {critical_floor}
    paths: {critical_paths}
  path_groups:
    src/training: {{floor: {group_floor}, target: 85}}
data_quality:
  pull_request_fixture_required: true
docstrings: {{}}
""".encode()


def test_test_policy_rejects_root_source_and_critical_manifest_weakening(
    tmp_path: Path,
) -> None:
    module = load_module("policy_non_regression_test_manifest")
    materialize(tmp_path)
    base = sample_policy()

    for mutation, message in (
        ({"test_roots": []}, "test_roots|outside"),
        ({"coverage_sources": []}, "coverage_sources"),
        (
            {
                "critical_tests": {
                    **base["critical_tests"],
                    "schema": [],
                }
            },
            "critical_tests.schema",
        ),
        ({"marker_exclusions": ["slow", "external"]}, "marker_exclusions"),
        (
            {
                "marker_exclusions": [],
                "registered_markers": [],
            },
            "registered_markers",
        ),
        ({"protected_support_files": []}, "protected_support_files"),
    ):
        head = json.loads(json.dumps(base))
        head.update(mutation)
        with pytest.raises(ValueError, match=message):
            module.validate_test_policy_non_regression(
                policy_bytes(base),
                policy_bytes(head),
                root=tmp_path,
            )


def test_test_and_coverage_policy_ratchets_are_permitted(tmp_path: Path) -> None:
    module = load_module("policy_non_regression_ratchet")
    materialize(tmp_path)
    base = sample_policy()
    head = json.loads(json.dumps(base))
    head["critical_tests"]["schema"].append("tests/test_new_schema.py")
    head["marker_exclusions"] = []

    module.validate_test_policy_non_regression(
        policy_bytes(base),
        policy_bytes(head),
        root=tmp_path,
    )
    module.validate_quality_debt_non_regression(
        quality_bytes(),
        quality_bytes(
            global_floor=55,
            diff_floor=97,
            critical_floor=98,
            critical_paths="[src/training/, src/inference/]",
            group_floor=50,
        ),
    )


@pytest.mark.parametrize(
    ("head", "message"),
    [
        (quality_bytes(global_floor=49), "global_floor"),
        (quality_bytes(diff_floor=94), "diff_floor"),
        (quality_bytes(critical_floor=94), "critical_patch.target"),
        (quality_bytes(critical_paths="[src/inference/]"), "critical_patch.paths"),
        (quality_bytes(group_floor=44), "path_groups.src/training.floor"),
        (
            quality_bytes().replace(
                b"  pull_request_fixture_required: true",
                b"  pull_request_fixture_required: false",
            ),
            "pull_request_fixture_required",
        ),
    ],
)
def test_quality_debt_floor_and_hook_weakening_is_rejected(
    head: bytes,
    message: str,
) -> None:
    module = load_module(f"policy_non_regression_quality_{message}")
    with pytest.raises(ValueError, match=message):
        module.validate_quality_debt_non_regression(quality_bytes(), head)


def test_protected_pyproject_tool_configuration_is_compared_separately() -> None:
    module = load_module("policy_non_regression_pyproject")
    base = b"""\
[project]
name = "example"
dependencies = ["one"]
[tool.ruff.lint]
select = ["E", "F"]
"""
    dependency_only = base.replace(b'"one"', b'"two"')
    weakened = base.replace(b'["E", "F"]', b'["E"]')

    assert module._protected_pyproject_tools(base) == module._protected_pyproject_tools(dependency_only)
    assert module._protected_pyproject_tools(base) != module._protected_pyproject_tools(weakened)


def test_coderabbit_configuration_is_exact_protected_policy() -> None:
    module = load_module("policy_non_regression_coderabbit")
    assert ".coderabbit.yaml" in module.EXACT_PROTECTED_CONFIGS
