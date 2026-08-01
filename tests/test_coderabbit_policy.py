from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_consumer.py"
PLATFORM_SHA = "a" * 40


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("validate_consumer_coderabbit", SCRIPT)
    assert spec and spec.loader
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def materialize_managed_tree(root: Path, module: ModuleType) -> None:
    template = ROOT / "templates" / "consumer"
    for workflow_path in module.MANAGED_WORKFLOWS:
        source = template / ".github" / "workflows" / Path(workflow_path).name
        target = root / workflow_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            source.read_text(encoding="utf-8").replace(
                "__CI_PLATFORM_FULL_SHA__",
                PLATFORM_SHA,
            ),
            encoding="utf-8",
        )
    evaluator = ".github/ci/evaluate_ai_provider.py"
    target_evaluator = root / evaluator
    target_evaluator.parent.mkdir(parents=True, exist_ok=True)
    target_evaluator.write_text(
        (template / evaluator).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (root / ".coderabbit.yaml").write_text(
        (template / ".coderabbit.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def test_managed_tree_requires_exact_coderabbit_configuration(tmp_path: Path) -> None:
    module = load_module()
    materialize_managed_tree(tmp_path, module)
    module._validate_managed_tree(
        tmp_path,
        platform_root=ROOT,
        lock_sha=PLATFORM_SHA,
        observed_paths=set(module.MANAGED_WORKFLOWS),
    )

    config = tmp_path / ".coderabbit.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "    enabled: false",
            "    enabled: true",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="CodeRabbit configuration"):
        module._validate_managed_tree(
            tmp_path,
            platform_root=ROOT,
            lock_sha=PLATFORM_SHA,
            observed_paths=set(module.MANAGED_WORKFLOWS),
        )
