from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY_SCRIPT = ROOT / "scripts" / "test_policy.py"
RUNNER_SCRIPT = ROOT / "scripts" / "run_test_policy.py"
SCHEMA = ROOT / "contract" / "test-policy-v1.schema.json"
TRUSTED_SITE = Path(pytest.__file__).resolve().parents[1]
CONSUMER_PRE_V1 = ROOT / "tests" / "fixtures" / "consumer-pre-v1"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def critical_consumer_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "test_roots": ["tests"],
        "marker_exclusions": ["slow", "external", "resource_heavy"],
        "registered_markers": [
            "slow",
            "external",
            "resource_heavy",
            "unit",
            "integration",
            "leakage",
            "critical",
            "smoke",
        ],
        "disabled_plugins": ["benchmark"],
        "protected_support_files": ["tests/conftest.py"],
        "coverage_sources": ["src", "tools"],
        "critical_tests": {
            "leakage": ["tests/test_leakage_contract.py"],
            "lineage": ["tests/test_lineage_contract.py"],
            "schema": ["tests/test_schema_contract.py"],
            "parity": ["tests/test_parity_contract.py"],
            "model": ["tests/test_model_contract.py"],
        },
        "unexpected_skip_policy": "fail",
    }


def materialize_policy_tree(root: Path) -> None:
    for relative in ("tests", "src", "tools"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "tests" / "conftest.py").write_text("# protected support\n", encoding="utf-8")
    for paths in critical_consumer_policy()["critical_tests"].values():
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("def test_placeholder():\n    assert True\n", encoding="utf-8")


def test_closed_test_policy_accepts_generic_critical_consumer_selectors(tmp_path: Path) -> None:
    module = load_module(POLICY_SCRIPT, "test_policy_valid")
    materialize_policy_tree(tmp_path)

    policy = module.validate_test_policy(critical_consumer_policy(), root=tmp_path)
    assert policy["marker_exclusions"] == ["slow", "external", "resource_heavy"]
    assert policy["registered_markers"] == critical_consumer_policy()["registered_markers"]
    assert policy["disabled_plugins"] == ["benchmark"]
    assert policy["coverage_sources"] == ["src", "tools"]
    assert set(policy["critical_tests"]) == {
        "leakage",
        "lineage",
        "model",
        "schema",
        "parity",
    }

    command = module.build_pytest_command(
        policy,
        junit_path=tmp_path / "pytest-junit.xml",
        coverage_xml=tmp_path / "coverage.xml",
        coverage_json=tmp_path / "coverage.json",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )
    assert command[:4] == [module.sys.executable, "-I", "-S", str(module.PYTEST_ENTRYPOINT)]
    assert "-p\0pytest_cov.plugin" in "\0".join(command)
    serialized = "\0".join(command)
    assert "-m\0not slow and not external and not resource_heavy" in serialized
    assert "-p\0no:benchmark" in serialized
    for source in policy["coverage_sources"]:
        assert f"--cov={source}" in command
    assert command[-1] == "tests"
    assert "--cov-branch" in command
    assert "-p\0xdist.plugin" not in serialized
    assert "-n" not in command
    assert "-p\0no:cacheprovider" in serialized
    assert "--rootdir\0." in serialized
    full_basetemp = module.pytest_basetemp_path(tmp_path / "pytest-junit.xml", "full")
    assert f"--basetemp={module.pytest_runtime_argument_path(full_basetemp, tmp_path)}" in command
    pytest_tail = command[command.index("--") + 1 :]
    assert not any(len(argument) >= 3 and argument[1:3] in {":\\", ":/"} for argument in pytest_tail)


def test_external_protected_pytest_config_runs_without_writing_the_target(tmp_path: Path) -> None:
    """Catches container execution trying to stage its config inside a read-only PR checkout."""
    module = load_module(POLICY_SCRIPT, "test_policy_external_protected_config")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_real.py").write_text("def test_real():\n    assert True\n", encoding="utf-8")
    command = module.build_fast_pytest_command(
        {
            "marker_exclusions": [],
            "disabled_plugins": [],
            "test_roots": ["tests"],
        },
        selected_tests=["tests/test_real.py"],
        junit_path=tmp_path / "external.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
        protected_pytest_config=module.PYTEST_CONFIG,
    )
    serialized = "\0".join(command)
    assert f"--protected-config\0{module.PYTEST_CONFIG.resolve()}" in serialized
    assert f"-c\0{module.PYTEST_CONFIG.resolve()}" in serialized
    assert ".ci-platform-pytest-config-" not in serialized

    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=module.pytest_subprocess_environment(),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(tmp_path.glob(".ci-platform-pytest-config-*"))


def test_protected_base_manifest_replaces_git_inside_the_runtime_and_revalidates_candidate_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches an unpinned runtime git dependency or a stale/forged protected test file."""
    module = load_module(POLICY_SCRIPT, "test_policy_protected_base_manifest")
    target = tmp_path / "target"
    target.mkdir()
    materialize_policy_tree(target)
    policy = critical_consumer_policy()
    protected = [
        path for category in sorted(module.CRITICAL_CATEGORIES) for path in policy["critical_tests"][category]
    ] + policy["protected_support_files"]
    manifest = {
        "schema_version": 1,
        "base_sha": "a" * 40,
        "policy": policy,
        "protected_sha256": {
            relative: hashlib.sha256(
                (target / relative).read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
            ).hexdigest()
            for relative in protected
        },
    }
    manifest_path = tmp_path / "protected-base.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("git must not run")),
    )

    observed, digest = module.load_policy_from_protected_manifest(
        target,
        manifest_path,
        "a" * 40,
    )
    assert observed == policy
    assert digest == module.canonical_policy_digest(policy)

    changed = Path(policy["critical_tests"]["leakage"][0])
    (target / changed).write_text("def test_replaced():\n    assert True\n", encoding="utf-8")
    with pytest.raises(ValueError, match="protected test/support bytes differ"):
        module.load_policy_from_protected_manifest(target, manifest_path, "a" * 40)


def test_pytest_basetemp_is_trusted_collision_resistant_and_rejects_escapes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_module(POLICY_SCRIPT, "test_policy_basetemp_boundary")
    first = module.pytest_basetemp_path(tmp_path / "one.xml", "full")
    repeat = module.pytest_basetemp_path(tmp_path / "one.xml", "full")
    other_junit = module.pytest_basetemp_path(tmp_path / "two.xml", "full")
    other_phase = module.pytest_basetemp_path(tmp_path / "one.xml", "critical")
    trusted_root = module.trusted_pytest_temp_root()

    assert first == repeat
    assert len({first, other_junit, other_phase}) == 3
    assert all(path.parent == trusted_root for path in (first, other_junit, other_phase))
    with pytest.raises(ValueError, match="escapes"):
        module.remove_pytest_basetemp_path(trusted_root / ".." / first.name)
    with pytest.raises(ValueError, match="escapes"):
        module.remove_pytest_basetemp_path(trusted_root / "ci-platform-pytest-full-not-a-digest")

    first.mkdir()
    original_is_symlink = module.pathlib.Path.is_symlink
    with monkeypatch.context() as patch:
        patch.setattr(
            module.pathlib.Path,
            "is_symlink",
            lambda path: path == first or original_is_symlink(path),
        )
        with pytest.raises(ValueError, match="not a regular directory"):
            module.remove_pytest_basetemp_path(first)
    first.rmdir()

    first.mkdir()
    candidate_inode = first.lstat().st_ino
    with monkeypatch.context() as patch:
        patch.setattr(
            module,
            "_is_reparse_point",
            lambda metadata: metadata.st_ino == candidate_inode,
        )
        with pytest.raises(ValueError, match="not a regular directory"):
            module.remove_pytest_basetemp_path(first)
    first.rmdir()


def test_isolated_pytest_config_is_bounded_collision_safe_and_rejects_reparse_points(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_module(POLICY_SCRIPT, "test_policy_config_boundary")
    basetemp = module.pytest_basetemp_path(tmp_path / "one.xml", "full")
    config_path = module.pytest_config_path(basetemp, tmp_path)

    assert config_path.parent.parent == tmp_path.resolve()
    assert config_path.name == "pytest.ini"
    fsync_sizes: list[int] = []
    real_fsync = module.os.fsync

    def record_fsync(descriptor: int) -> None:
        fsync_sizes.append(module.os.fstat(descriptor).st_size)
        real_fsync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "fsync", record_fsync)
        staged = module.stage_pytest_config(basetemp, tmp_path)
    assert fsync_sizes == [len(module.PYTEST_CONFIG.read_bytes())]
    assert staged == config_path
    assert staged.read_bytes() == module.PYTEST_CONFIG.read_bytes()
    assert not staged.stat().st_mode & (module.stat.S_IWUSR | module.stat.S_IWGRP | module.stat.S_IWOTH)
    with pytest.raises(FileExistsError):
        module.stage_pytest_config(basetemp, tmp_path)
    module.remove_pytest_config(basetemp, tmp_path, required=True)
    assert not config_path.parent.exists()

    with pytest.raises(ValueError, match="escapes"):
        module.remove_pytest_config_path(tmp_path / ".." / config_path.parent.name, tmp_path)
    with pytest.raises(ValueError, match="escapes"):
        module.remove_pytest_config_path(tmp_path / ".ci-platform-pytest-config-not-a-digest", tmp_path)

    config_path.parent.mkdir()
    original_is_symlink = module.pathlib.Path.is_symlink
    with monkeypatch.context() as patch:
        patch.setattr(
            module.pathlib.Path,
            "is_symlink",
            lambda path: path == config_path.parent or original_is_symlink(path),
        )
        with pytest.raises(ValueError, match="not a regular directory"):
            module.remove_pytest_config_path(config_path.parent, tmp_path)
    config_path.parent.rmdir()

    config_path.parent.mkdir()
    candidate_inode = config_path.parent.lstat().st_ino
    with monkeypatch.context() as patch:
        patch.setattr(
            module,
            "_is_reparse_point",
            lambda metadata: metadata.st_ino == candidate_inode,
        )
        with pytest.raises(ValueError, match="not a regular directory"):
            module.remove_pytest_config_path(config_path.parent, tmp_path)
    config_path.parent.rmdir()


def test_pytest_config_staging_uses_a_non_sensitive_name_and_preserves_atomic_durability() -> None:
    """Catches a heuristic-sensitive helper name or weakened exclusive durable staging."""
    source = POLICY_SCRIPT.read_text(encoding="utf-8")
    assert "_trusted_pytest_config_bytes" not in source
    assert "def _immutable_pytest_ini_bytes() -> bytes:" in source
    assert 'with config_path.open("xb") as handle:' in source
    assert "handle.write(_immutable_pytest_ini_bytes())" in source
    assert "handle.flush()" in source
    assert "os.fsync(handle.fileno())" in source
    assert "config_path.chmod(stat.S_IREAD)" in source


def test_generic_pre_v1_policy_remains_a_named_migration_blocker(
    tmp_path: Path,
) -> None:
    """Catches claiming consumer readiness before the actual legacy policy gains protected v1 fields."""
    module = load_module(POLICY_SCRIPT, "test_policy_consumer_pre_v1_migration")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ci-platform-test-policy.json").write_bytes(
        (CONSUMER_PRE_V1 / ".github" / "ci-platform-test-policy.json").read_bytes()
    )
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "base"],
        cwd=tmp_path,
        check=True,
    )
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    with pytest.raises(ValueError, match="closed v1 schema"):
        module.load_policy_from_base(tmp_path, base_sha)
    contract = json.loads((ROOT / "contract" / "v1.json").read_text(encoding="utf-8"))
    assert "first-critical-consumer-test-policy-v1-migration" in contract["x-merge-gate-v1"]["release_blockers"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"command": "pytest tests"}, "keys"),
        ({"unexpected_skip_policy": "allow"}, "unexpected_skip_policy"),
        ({"marker_exclusions": ["unit"]}, "marker"),
        ({"disabled_plugins": ["cov"]}, "plugin"),
        ({"test_roots": ["../tests"]}, "path"),
        ({"coverage_sources": ["--cov=attacker"]}, "coverage"),
    ],
)
def test_test_policy_rejects_commands_weakening_and_unsafe_paths(
    tmp_path: Path,
    mutation: dict[str, Any],
    message: str,
) -> None:
    module = load_module(POLICY_SCRIPT, f"test_policy_invalid_{message}")
    materialize_policy_tree(tmp_path)
    candidate = critical_consumer_policy()
    candidate.update(mutation)
    with pytest.raises(ValueError, match=message):
        module.validate_test_policy(candidate, root=tmp_path)


def test_critical_profile_requires_all_explicit_manifest_categories(
    tmp_path: Path,
) -> None:
    module = load_module(POLICY_SCRIPT, "test_policy_critical")
    materialize_policy_tree(tmp_path)
    candidate = critical_consumer_policy()
    candidate["critical_tests"]["lineage"] = []
    policy = module.validate_test_policy(candidate, root=tmp_path)
    with pytest.raises(ValueError, match="lineage"):
        module.validate_profile_policy(policy, "critical-ml")
    module.validate_profile_policy(policy, "python")


@pytest.mark.parametrize("profile", ["node", "powershell"])
def test_non_python_profiles_do_not_require_python_test_or_coverage_roots(
    tmp_path: Path,
    profile: str,
) -> None:
    """Catches treating Node or PowerShell consumers as Python-only profiles."""
    module = load_module(POLICY_SCRIPT, f"test_policy_{profile}")
    policy = module.validate_test_policy(
        {
            **critical_consumer_policy(),
            "test_roots": [],
            "coverage_sources": [],
            "protected_support_files": [],
            "critical_tests": {
                "leakage": [],
                "lineage": [],
                "model": [],
                "parity": [],
                "schema": [],
            },
        }
    )

    module.validate_profile_policy(policy, profile)


def test_critical_rerun_ignores_marker_exclusions_and_executes_every_file(
    tmp_path: Path,
) -> None:
    policy_module = load_module(POLICY_SCRIPT, "test_policy_unfiltered_critical")
    runner_module = load_module(RUNNER_SCRIPT, "run_policy_unfiltered_critical")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    slow: deliberately excluded from the ordinary suite\n",
        encoding="utf-8",
    )
    files = {
        "leakage": "tests/test_slow_leakage.py",
        "lineage": "tests/test_lineage.py",
        "model": "tests/test_model.py",
        "parity": "tests/test_parity.py",
        "schema": "tests/test_schema.py",
    }
    for category, relative in files.items():
        marker = "import pytest\n\n" + "@pytest.mark.slow\n" if category == "leakage" else ""
        (tmp_path / relative).write_text(
            f"{marker}def test_{category}():\n    assert True\n",
            encoding="utf-8",
        )
    policy = {
        "marker_exclusions": ["slow"],
        "disabled_plugins": ["benchmark"],
        "critical_tests": {category: [relative] for category, relative in files.items()},
    }
    junit = tmp_path / "critical.xml"
    collect_command = policy_module.build_critical_command(
        policy,
        junit_path=junit,
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
        collect_only=True,
    )
    run_command = policy_module.build_critical_command(
        policy,
        junit_path=junit,
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )

    assert collect_command[:4] == [
        policy_module.sys.executable,
        "-I",
        "-S",
        str(policy_module.PYTEST_ENTRYPOINT),
    ]
    assert run_command[:4] == [
        policy_module.sys.executable,
        "-I",
        "-S",
        str(policy_module.PYTEST_ENTRYPOINT),
    ]
    assert "not slow" not in "\0".join(collect_command + run_command)
    assert "-m\0" in "\0".join(run_command)
    assert "addopts=" in run_command
    assert "-p\0xdist.plugin" not in "\0".join(run_command)
    assert "-p\0no:cacheprovider" in "\0".join(collect_command + run_command)
    basetemp_path = policy_module.pytest_basetemp_path(junit, "critical")
    critical_basetemp = f"--basetemp={policy_module.pytest_runtime_argument_path(basetemp_path, tmp_path)}"
    assert critical_basetemp in collect_command
    assert critical_basetemp in run_command
    collection = subprocess.run(
        collect_command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        env=policy_module.pytest_subprocess_environment(),
    )
    assert collection.returncode == 0, (collection.stdout + collection.stderr).decode(
        "utf-8",
        errors="replace",
    )
    selected = [files[category] for category in sorted(files)]
    nodeids, counts = runner_module._critical_collection(
        collection.stdout,
        selected,
    )
    subprocess.run(
        run_command,
        cwd=tmp_path,
        check=True,
        env=policy_module.pytest_subprocess_environment(),
    )

    assert len(nodeids) == 5
    assert counts == {relative: 1 for relative in selected}
    assert runner_module._junit_counts(junit)["tests"] == 5
    assert not (tmp_path / ".pytest_cache").exists()


def test_xdist_is_optional_and_never_force_registered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Catches explicit xdist registration colliding with pytest's normal autoload."""
    module = load_module(POLICY_SCRIPT, "test_policy_optional_xdist")
    monkeypatch.delenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", raising=False)
    normal_command = module.build_critical_command(
        {
            "disabled_plugins": [],
            "protected_support_files": [],
            "critical_tests": {category: [f"tests/test_{category}.py"] for category in module.CRITICAL_CATEGORIES},
        },
        junit_path=tmp_path / "normal.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    hermetic_command = module.build_critical_command(
        {
            "disabled_plugins": [],
            "critical_tests": {category: [f"tests/test_{category}.py"] for category in module.CRITICAL_CATEGORIES},
        },
        junit_path=tmp_path / "hermetic.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )

    assert ["-p", "xdist.plugin"] not in [normal_command[index : index + 2] for index in range(len(normal_command))]
    assert ["-n", "auto"] not in [normal_command[index : index + 2] for index in range(len(normal_command))]
    assert ["-n", "auto"] not in [hermetic_command[index : index + 2] for index in range(len(hermetic_command))]


def test_critical_policy_executes_with_plugin_autoload_disabled_without_checkout_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches policy coverage options becoming unknown when autoload is disabled."""
    runner = load_module(RUNNER_SCRIPT, "run_policy_hermetic_execution")
    policy_module = load_module(POLICY_SCRIPT, "test_policy_hermetic_execution")
    (tmp_path / ".github").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    critical_tests = {category: [f"tests/test_{category}.py"] for category in sorted(runner.CRITICAL_CATEGORIES)}
    for category, paths in critical_tests.items():
        (tmp_path / paths[0]).write_text(
            f"from src import VALUE\n\ndef test_{category}():\n    assert VALUE == 1\n",
            encoding="utf-8",
        )
    policy = {
        "version": 1,
        "test_roots": ["tests"],
        "marker_exclusions": [],
        "registered_markers": [],
        "disabled_plugins": [],
        "protected_support_files": [],
        "coverage_sources": ["src"],
        "critical_tests": critical_tests,
        "unexpected_skip_policy": "fail",
    }
    (tmp_path / ".github" / "ci-platform-test-policy.json").write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-m", "base"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    summary = runner.run_policy(
        root=tmp_path,
        base_sha=base_sha,
        profile="critical-ml",
        evidence_dir=tmp_path / "evidence",
        coverage_xml=tmp_path / "coverage.xml",
        coverage_json=tmp_path / "coverage.json",
        trusted_site=TRUSTED_SITE,
    )

    assert summary["status"] == "passed"
    assert summary["test_counts"]["tests"] == 5
    assert not (tmp_path / ".pytest_cache").exists()
    assert not policy_module.pytest_basetemp_path(tmp_path / "evidence" / "pytest-junit.xml", "full").exists()
    assert not policy_module.pytest_basetemp_path(
        tmp_path / ".ci-platform-critical-pytest-junit.xml", "critical"
    ).exists()


def test_protected_critical_and_support_bytes_cannot_be_replaced_by_candidate(tmp_path: Path) -> None:
    """Catches a PR replacing leakage hooks or conftest support with passing stubs."""
    module = load_module(POLICY_SCRIPT, "test_policy_protected_bytes")
    materialize_policy_tree(tmp_path)
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ci-platform-test-policy.json").write_text(
        json.dumps(critical_consumer_policy()),
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-m", "base"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    critical = Path(critical_consumer_policy()["critical_tests"]["leakage"][0])
    original = (tmp_path / critical).read_bytes()
    (tmp_path / critical).write_text("def test_stub():\n    assert True\n", encoding="utf-8")
    with pytest.raises(ValueError, match="protected test/support bytes differ"):
        module.load_policy_from_base(tmp_path, base_sha)

    (tmp_path / critical).write_bytes(original)
    (tmp_path / "tests" / "conftest.py").write_text("# forged support\n", encoding="utf-8")
    with pytest.raises(ValueError, match="protected test/support bytes differ"):
        module.load_policy_from_base(tmp_path, base_sha)

    (tmp_path / "tests" / "conftest.py").write_text("# protected support\n", encoding="utf-8")
    nested = tmp_path / "tests" / "nested"
    nested.mkdir()
    (nested / "conftest.py").write_text(
        "def pytest_collection_modifyitems(items):\n    items.clear()\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unprotected conftest"):
        module.load_policy_from_base(tmp_path, base_sha)


def test_isolated_pytest_entrypoint_cannot_be_shadowed_by_target_module(tmp_path: Path) -> None:
    """Catches a target pytest.py replacing the central runner before a real failure executes."""
    module = load_module(POLICY_SCRIPT, "test_policy_shadowed_pytest")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pytest.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    (tmp_path / "tests" / "test_failure.py").write_text(
        "def test_real_failure():\n    assert False\n",
        encoding="utf-8",
    )
    command = module.build_fast_pytest_command(
        {
            "marker_exclusions": [],
            "disabled_plugins": [],
            "test_roots": ["tests"],
        },
        selected_tests=["tests/test_failure.py"],
        junit_path=tmp_path / "failure.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )

    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=module.pytest_subprocess_environment(),
    )

    assert result.returncode == 1
    assert "test_real_failure" in result.stdout
    fast_basetemp = module.pytest_basetemp_path(tmp_path / "failure.xml", "fast")
    assert f"--basetemp={module.pytest_runtime_argument_path(fast_basetemp, tmp_path)}" in command


def test_isolated_pytest_ignores_target_sitecustomize_pth_and_entrypoint_plugins(
    tmp_path: Path,
) -> None:
    """Catches target dependency startup hooks executing before trusted pytest/plugins."""
    module = load_module(POLICY_SCRIPT, "test_policy_target_site_hooks")
    target = tmp_path / "target"
    target_site = tmp_path / "target-site"
    target.mkdir()
    target_site.mkdir()
    (target / "tests").mkdir()
    sentinel = tmp_path / "platform-sentinel.txt"
    sentinel.write_text("immutable\n", encoding="utf-8")
    payload = f"from pathlib import Path; Path({str(sentinel)!r}).write_text('mutated')\n"
    (target_site / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (target_site / "attack.pth").write_text("import sitecustomize\n", encoding="utf-8")
    (target_site / "dependency.py").write_text("VALUE = 7\n", encoding="utf-8")
    (target / "pytest.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    (target / "tests" / "test_dependency.py").write_text(
        "from dependency import VALUE\n\ndef test_dependency():\n    assert VALUE == 7\n",
        encoding="utf-8",
    )
    command = module.build_fast_pytest_command(
        {
            "marker_exclusions": [],
            "disabled_plugins": [],
            "test_roots": ["tests"],
        },
        selected_tests=["tests/test_dependency.py"],
        junit_path=tmp_path / "hooks.xml",
        trusted_site=TRUSTED_SITE,
        target_root=target,
        target_site=target_site,
    )

    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=module.pytest_subprocess_environment(),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_text(encoding="utf-8") == "immutable\n"


def test_critical_collection_rejects_an_entirely_deselected_file() -> None:
    module = load_module(RUNNER_SCRIPT, "run_policy_deselected_critical")
    output = b"tests/test_other.py::test_ok\n\n1 test collected\n"
    with pytest.raises(ValueError, match="every protected critical test file"):
        module._critical_collection(
            output,
            ["tests/test_other.py", "tests/test_slow.py"],
        )


@pytest.mark.parametrize(
    ("config_name", "config_body"),
    [
        ("pytest.toml", '[pytest]\naddopts = ["--collect-only"]\n'),
        (".pytest.toml", '[pytest]\naddopts = ["--collect-only"]\n'),
        ("pytest.ini", "[pytest]\naddopts = --collect-only\n"),
        (".pytest.ini", "[pytest]\naddopts = --collect-only\n"),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "--collect-only"\n'),
        ("tox.ini", "[pytest]\naddopts = --collect-only\n"),
        ("setup.cfg", "[tool:pytest]\naddopts = --collect-only\n"),
    ],
)
def test_full_policy_rejects_pr_owned_collect_only_and_zero_test_junit(
    tmp_path: Path,
    config_name: str,
    config_body: str,
) -> None:
    """Catches PR-owned pytest configuration converting a required run into collection-only success."""
    module = load_module(POLICY_SCRIPT, "test_policy_pr_addopts")
    runner = load_module(RUNNER_SCRIPT, "run_policy_zero_tests")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_real.py").write_text("def test_real():\n    assert True\n", encoding="utf-8")
    (tmp_path / config_name).write_text(config_body, encoding="utf-8")
    command = module.build_fast_pytest_command(
        {
            "marker_exclusions": [],
            "disabled_plugins": [],
            "test_roots": ["tests"],
        },
        selected_tests=["tests/test_real.py"],
        junit_path=tmp_path / "real.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )
    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=module.pytest_subprocess_environment(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert runner._junit_counts(tmp_path / "real.xml")["tests"] == 1
    assert not any(tmp_path.glob(".ci-platform-pytest-config-*"))

    zero = tmp_path / "zero.xml"
    zero.write_text(
        '<?xml version="1.0"?><testsuites tests="0" failures="0" errors="0" skipped="0"/>\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="zero executed"):
        runner._junit_counts(zero)


@pytest.mark.parametrize("attack", ["delete", "modify"])
def test_isolated_pytest_fails_if_target_tampers_with_staged_config(
    tmp_path: Path,
    attack: str,
) -> None:
    """Catches target imports changing or deleting the immutable config before cleanup validation."""
    module = load_module(POLICY_SCRIPT, f"test_policy_config_tamper_{attack}")
    (tmp_path / "tests").mkdir()
    action = (
        "config.chmod(stat.S_IREAD | stat.S_IWRITE)\n    config.unlink()"
        if attack == "delete"
        else (
            "config.chmod(stat.S_IREAD | stat.S_IWRITE)\n"
            "    config.write_text('[pytest]\\naddopts = --collect-only\\n', encoding='utf-8')"
        )
    )
    (tmp_path / "tests" / "test_attack.py").write_text(
        "import stat\n"
        "from pathlib import Path\n\n"
        "config_directories = list(Path.cwd().glob('.ci-platform-pytest-config-*'))\n"
        "assert len(config_directories) == 1\n"
        "config = config_directories[0] / 'pytest.ini'\n"
        "assert config.is_file()\n\n"
        "def test_attack():\n"
        f"    {action}\n",
        encoding="utf-8",
    )
    command = module.build_fast_pytest_command(
        {
            "marker_exclusions": [],
            "disabled_plugins": [],
            "test_roots": ["tests"],
        },
        selected_tests=["tests/test_attack.py"],
        junit_path=tmp_path / "attack.xml",
        trusted_site=TRUSTED_SITE,
        target_root=tmp_path,
    )

    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=module.pytest_subprocess_environment(),
    )

    assert result.returncode != 0
    assert "pytest config" in result.stderr
    leftovers = list(tmp_path.glob(".ci-platform-pytest-config-*"))
    if attack == "delete":
        assert len(leftovers) == 1
        leftovers[0].rmdir()
    else:
        assert leftovers == []


def test_policy_schema_is_closed_and_matches_manual_contract() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "version",
        "test_roots",
        "marker_exclusions",
        "registered_markers",
        "disabled_plugins",
        "protected_support_files",
        "coverage_sources",
        "critical_tests",
        "unexpected_skip_policy",
    }
    assert schema["properties"]["version"]["const"] == 1
    assert schema["properties"]["unexpected_skip_policy"]["const"] == "fail"
    assert schema["properties"]["critical_tests"]["additionalProperties"] is False
    assert set(schema["properties"]["critical_tests"]["required"]) == {
        "leakage",
        "lineage",
        "model",
        "schema",
        "parity",
    }


def test_runner_is_structured_and_has_no_command_input() -> None:
    raw = RUNNER_SCRIPT.read_text(encoding="utf-8")
    assert "shell=True" not in raw
    assert '--command"' not in raw
    assert 'policy["command"]' not in raw
    assert "free-form" not in raw.lower()
    assert "load_policy_from_base" in raw
    assert "unexpected_skip_policy" in raw
