from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_repository_hooks.py"
BASE = "b" * 40


def load_module(name: str = "repository_hooks") -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy() -> dict[str, Any]:
    return {
        "docstrings": {"baseline_missing": 1},
        "data_quality": {"pull_request_fixture_required": True},
        "coverage": {
            "diff_floor": 95,
            "critical_patch": {
                "target": 95,
                "paths": ["src/critical_contract.py"],
            },
            "path_groups": {"src/training": {"floor": 45, "target": 85}},
        },
    }


def test_policy_selects_all_critical_repository_native_hooks() -> None:
    module = load_module()
    assert module.required_hooks("baseline", policy()) == set()
    assert module.required_hooks("python", policy()) == {
        "docstrings",
        "data-quality",
        "path-group-coverage",
        "coverage-ratchet",
    }
    assert module.required_hooks("critical-ml", policy()) == {
        "docstrings",
        "data-quality",
        "column-signatures",
        "rebuild-smoke",
        "path-group-coverage",
        "coverage-ratchet",
    }


def test_critical_profile_fails_when_any_fixed_hook_is_absent(
    tmp_path: Path,
) -> None:
    module = load_module("repository_hooks_missing")
    for relative in module.CRITICAL_REQUIRED_PATHS[:-1]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8")
    with pytest.raises(ValueError, match="check_coverage_ratchet"):
        module.validate_required_files(tmp_path, "critical-ml")


def test_post_coverage_invokes_native_group_diff_and_ratchet_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("repository_hooks_post")
    (tmp_path / "tools").mkdir()
    for name in (
        "normalize_coverage_paths.py",
        "check_module_coverage.py",
        "check_coverage_ratchet.py",
    ):
        (tmp_path / "tools" / name).write_text("# fixture\n", encoding="utf-8")
    coverage = tmp_path / "coverage.xml"
    coverage.write_text("<coverage/>\n", encoding="utf-8")
    registry = tmp_path / "protected-quality-debt.yml"
    registry.write_text("coverage: {}\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        timeout: int = 1800,
    ) -> None:
        del cwd, timeout
        commands.append(command)
        if command[0] == "diff-cover":
            output = next(value.removeprefix("json:") for value in command if value.startswith("json:"))
            Path(output).write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(module, "_run", fake_run)
    executed = module._run_post_coverage(
        tmp_path,
        profile="critical-ml",
        base_sha=BASE,
        registry=policy(),
        registry_path=registry,
        coverage_xml=coverage,
        evidence_dir=evidence,
    )
    assert executed == [
        "normalize-coverage",
        "path-group-coverage",
        "coverage-ratchet",
    ]
    flattened = [" ".join(command) for command in commands]
    assert any("tools/check_module_coverage.py" in value for value in flattened)
    assert any(
        value.startswith("diff-cover ") and f"--compare-branch={BASE}" in value and "--fail-under=95" in value
        for value in flattened
    )
    assert any("tools/check_coverage_ratchet.py" in value for value in flattened)


def test_data_quality_hook_is_generic_required_and_fail_closed() -> None:
    module = load_module("repository_hooks_fixture")
    assert module.DATA_QUALITY_COMMAND == ("tools/check_data_quality_contract.py", "--ci")
    assert "tools/check_schema_contract.py" in module.CRITICAL_REQUIRED_PATHS
    assert "tools/check_rebuild_contract.py" in module.CRITICAL_REQUIRED_PATHS
