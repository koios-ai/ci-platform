from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_quality_canaries.py"
QUALITY_MAP = ROOT / "contract" / "deterministic-quality-v1.json"


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_quality_canaries", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_runner(map_path: Path = QUALITY_MAP, *, root: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RUNNER), "--root", str(root), "--map", str(map_path)],
        text=True,
        capture_output=True,
        check=False,
    )


def copy_quality_fixture(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "platform"
    map_path = root / "contract" / "deterministic-quality-v1.json"
    map_path.parent.mkdir(parents=True)
    shutil.copy2(QUALITY_MAP, map_path)
    shutil.copytree(ROOT / "tests" / "canaries" / "quality", root / "tests" / "canaries" / "quality")
    return root, map_path


def test_quality_canary_runner_executes_all_declared_owner_rules() -> None:
    """Catches a map whose negative fixtures exist but are never exercised by their owner."""
    result = run_runner()

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert set(report["executed"]) == {
        "wrong-arguments",
        "multiple-definition",
        "identical-expression-comparison",
        "undefined-export",
        "unreachable-statements",
        "calls-to-non-callables",
        "exit-quit",
        "conflicting-attributes",
        "implicit-list-string-concatenation",
    }


def test_quality_canary_runner_rejects_a_missing_negative_fixture(tmp_path: Path) -> None:
    """Catches an owner map silently retaining a non-existent negative canary path."""
    candidate = json.loads(QUALITY_MAP.read_text(encoding="utf-8"))
    candidate["classes"]["wrong-arguments"]["negative_canary"] = "tests/canaries/quality/missing.py"
    path = tmp_path / "quality.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")

    result = run_runner(path)

    assert result.returncode != 0
    assert "missing.py" in result.stderr


def test_quality_canary_runner_queries_installed_versions_and_rejects_mismatch() -> None:
    """Catches treating a version string in the owner map as proof of the executable actually used."""
    module = load_runner()

    with pytest.raises(ValueError, match="installed"):
        module.run(
            ROOT,
            QUALITY_MAP,
            version_resolver=lambda package: "0.0.0" if package == "ruff" else "1.19.1",
        )


def test_quality_canary_runner_requires_the_production_static_configs(tmp_path: Path) -> None:
    """Catches canaries silently running with tool defaults instead of production policy."""
    root, map_path = copy_quality_fixture(tmp_path)

    result = run_runner(map_path, root=root)

    assert result.returncode != 0
    assert "production config" in result.stderr


def test_quality_canary_runner_rejects_the_wrong_nonzero_diagnostic(tmp_path: Path) -> None:
    """Catches any unrelated mypy failure being accepted as the declared call-arg proof."""
    root, map_path = copy_quality_fixture(tmp_path)
    shutil.copy2(ROOT / "contract" / "ruff-v1.toml", root / "contract" / "ruff-v1.toml")
    shutil.copy2(ROOT / "contract" / "mypy-v1.ini", root / "contract" / "mypy-v1.ini")
    (root / "tests" / "canaries" / "quality" / "wrong_arguments.py").write_text(
        "missing_name\n",
        encoding="utf-8",
    )

    result = run_runner(map_path, root=root)

    assert result.returncode != 0
    assert "call-arg" in result.stderr


def test_batched_negative_diagnostics_must_bind_to_their_exact_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches accepting a diagnostic emitted for a different canary in the same tool batch."""
    module = load_runner()
    misplaced = "\n\n".join(
        (
            "tests/canaries/quality/wrong_arguments.py:1: error [assignment]",
            "tests/canaries/quality/conflicting_attributes.py:1: error [call-arg]",
            "tests/canaries/quality/unreachable_statements.py:1: error [operator]",
            "tests/canaries/quality/calls_to_non_callables.py:1: error [unreachable]",
            "tests/canaries/quality/multiple_definition.py:1: F822",
            "tests/canaries/quality/undefined_export.py:1: F811",
            "tests/canaries/quality/identical_expression_comparison.py:1: ISC004",
            "tests/canaries/quality/implicit_list_string_concatenation.py:1: PLR1722",
            "tests/canaries/quality/exit_quit.py:1: PLR0124",
        )
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        positive = all("_positive.py" in argument for argument in command if argument.endswith(".py"))
        return subprocess.CompletedProcess(command, 0 if positive else 1, "" if positive else misplaced, "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="fixture-specific"):
        module.run(
            ROOT,
            QUALITY_MAP,
            version_resolver=lambda package: {"ruff": "0.14.14", "mypy": "1.19.1"}[package],
        )
