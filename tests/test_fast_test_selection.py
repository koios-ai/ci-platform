from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TRUSTED_SITE = Path(pytest.__file__).resolve().parents[1]
PREFLIGHT = ROOT / ".github" / "actions" / "final-preflight" / "preflight.py"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy() -> dict[str, Any]:
    return {
        "version": 1,
        "test_roots": ["tests"],
        "marker_exclusions": ["slow"],
        "registered_markers": ["slow"],
        "disabled_plugins": ["benchmark"],
        "protected_support_files": [],
        "coverage_sources": ["src"],
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
    (root / "src" / "utils").mkdir(parents=True)
    (root / "src" / "features").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "utils" / "helper.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    (root / "src" / "utils" / "unmapped.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    (root / "src" / "features" / "ranking.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    for paths in policy()["critical_tests"].values():
        for relative in paths:
            (root / relative).write_text(
                "def test_placeholder():\n    assert True\n",
                encoding="utf-8",
            )
    (root / "tests" / "test_helper.py").write_text(
        "from src.utils import helper\n\ndef test_helper():\n    assert helper.VALUE == 1\n",
        encoding="utf-8",
    )


def test_fast_selection_uses_direct_imports_and_never_falls_back_to_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load_module(
        SCRIPTS / "fast_test_selection.py",
        "fast_test_selection_direct",
    )
    materialize(tmp_path)

    assert module.select_fast_tests(
        policy(),
        root=tmp_path,
        changed_paths=["src/utils/helper.py"],
    ) == ["tests/test_helper.py"]
    assert (
        module.select_fast_tests(
            policy(),
            root=tmp_path,
            changed_paths=["src/utils/unmapped.py"],
        )
        == []
    )


def test_fast_selection_expands_critical_changes_only_to_explicit_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load_module(
        SCRIPTS / "fast_test_selection.py",
        "fast_test_selection_critical",
    )
    materialize(tmp_path)

    selected = module.select_fast_tests(
        policy(),
        root=tmp_path,
        changed_paths=["src/features/ranking.py"],
    )
    assert selected == sorted(path for values in policy()["critical_tests"].values() for path in values)
    assert "tests/test_helper.py" not in selected


def test_fast_selection_accepts_changed_declared_tests_and_rejects_escape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load_module(
        SCRIPTS / "fast_test_selection.py",
        "fast_test_selection_roots",
    )
    materialize(tmp_path)
    (tmp_path / "integration").mkdir()
    (tmp_path / "integration" / "test_outside.py").write_text(
        "def test_outside():\n    assert True\n",
        encoding="utf-8",
    )

    assert module.select_fast_tests(
        policy(),
        root=tmp_path,
        changed_paths=["tests/test_helper.py"],
    ) == ["tests/test_helper.py"]
    with pytest.raises(ValueError, match="outside protected test roots"):
        module.select_fast_tests(
            policy(),
            root=tmp_path,
            changed_paths=["integration/test_outside.py"],
        )


def test_fast_pytest_command_is_structured_selected_only_and_skip_strict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load_module(SCRIPTS / "test_policy.py", "test_policy_fast_command")
    command = module.build_fast_pytest_command(
        policy(),
        selected_tests=["tests/test_helper.py"],
        junit_path=tmp_path / "fast-junit.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )

    assert command[:4] == [module.sys.executable, "-I", "-S", str(module.PYTEST_ENTRYPOINT)]
    assert command[-1] == "tests/test_helper.py"
    assert "tests" not in command
    assert f"--junitxml={module.pytest_runtime_argument_path(tmp_path / 'fast-junit.xml', tmp_path)}" in command
    plugin_selectors = [command[index : index + 2] for index in range(len(command))]
    assert ["-p", "no:benchmark"] in plugin_selectors
    assert ["-p", "no:cacheprovider"] in plugin_selectors
    marker_index = command.index("not slow")
    assert command[marker_index - 1 : marker_index + 1] == ["-m", "not slow"]
    assert "-W" in command and "error" in command
    assert not any(value.startswith("--cov") for value in command)


def test_fast_selection_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load_module(
        SCRIPTS / "fast_test_selection.py",
        "fast_test_selection_bound",
    )
    materialize(tmp_path)
    monkeypatch.setattr(module, "MAX_FAST_TESTS", 4)

    with pytest.raises(ValueError, match="bounded maximum"):
        module.select_fast_tests(
            policy(),
            root=tmp_path,
            changed_paths=["src/features/ranking.py"],
        )


def test_fast_runner_revalidates_selection_and_has_no_command_escape_hatch() -> None:
    raw = (SCRIPTS / "run_fast_tests.py").read_text(encoding="utf-8")
    assert "build_selection(" in raw
    assert "build_fast_pytest_command(" in raw
    assert "_junit_counts(" in raw
    assert "timeout=600" in raw
    assert "shell=True" not in raw
    assert "test_roots" not in raw
    assert '--command"' not in raw


def test_fast_and_final_profile_classifiers_share_the_critical_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    fast = load_module(
        SCRIPTS / "fast_test_selection.py",
        "fast_test_selection_profile",
    )
    preflight = load_module(PREFLIGHT, "final_preflight_profile")

    assert fast.CRITICAL_MARKERS == preflight.CRITICAL_MARKERS
    assert fast.CRITICAL_EXACT_PATHS == preflight.CRITICAL_EXACT_PATHS
    assert fast.CRITICAL_PREFIXES == preflight.CRITICAL_PREFIXES
    cases = [
        ["README.md"],
        ["src/helpers.py"],
        ["requirements.txt"],
        ["requirements-core-next.txt"],
        ["quality_debt.yml"],
        [".github/ci-platform-test-policy.json"],
        [".deepsource.toml"],
        ["tools/check_schema_contract.py"],
        ["tools/check_data_quality_contract.py"],
        ["tests/test_repository_gate.py"],
        ["src/features/ranking.py"],
        ["tests/test_model_contract.py"],
    ]
    for paths in cases:
        assert fast.classify_profile(paths) == preflight.classify_profile(paths)
    assert fast.classify_profile(["README.md"]) == "baseline"
    assert fast.classify_profile(["src/helpers.py"]) == "python"
    for paths in cases[2:]:
        assert fast.classify_profile(paths) == "critical-ml"
