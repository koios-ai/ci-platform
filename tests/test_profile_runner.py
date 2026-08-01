from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "profile_runner.py"
PINNED_REQUIREMENTS = "ruff==0.14.14\nmypy==1.19.1\nbandit==1.9.4\npip-audit==2.10.0\n"


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("profile_runner", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_security_platform(platform: Path) -> None:
    (platform / "contract").mkdir(parents=True, exist_ok=True)
    (platform / "scripts").mkdir(parents=True, exist_ok=True)
    config = b'{"pinned":"test"}\n'
    (platform / "contract" / "secret-scan-v1.json").write_bytes(config)
    (platform / "scripts" / "secret_scan.py").write_text("", encoding="utf-8")
    (platform / "scripts" / "run_module_isolated.py").write_text("", encoding="utf-8")
    (platform / "scripts" / "validate_node_test_policy.py").write_text("", encoding="utf-8")
    (platform / "contract" / "ruff-v1.toml").write_text(
        (ROOT / "contract" / "ruff-v1.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (platform / "contract" / "mypy-v1.ini").write_text(
        (ROOT / "contract" / "mypy-v1.ini").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (platform / "contract" / "bandit-v1.ini").write_text(
        (ROOT / "contract" / "bandit-v1.ini").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    contract = {
        "x-merge-gate-v1": {
            "common_security": {
                "status": "required-all-profiles",
                "tool": "scripts/secret_scan.py",
                "tool_version": "1.0.0",
                "config": "contract/secret-scan-v1.json",
                "config_sha256": hashlib.sha256(config).hexdigest(),
                "target_scope": "git-tracked-files",
                "target_code_execution": False,
            }
        }
    }
    (platform / "contract" / "v1.json").write_text(json.dumps(contract), encoding="utf-8")


def test_node_profile_requires_exactly_one_supported_lockfile_and_uses_its_manager(tmp_path: Path) -> None:
    """Catches Node admission falling back to npm when a lockfile is missing or ambiguous."""
    module = load_runner()
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@10.4.1", "scripts": {"test": "vitest run"}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="lockfile"):
        module.plan("node", tmp_path)

    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'", encoding="utf-8")
    platform = tmp_path / "platform"
    write_security_platform(platform)
    deterministic = module.plan(
        "node",
        tmp_path,
        platform_root=platform,
        base_sha="a" * 40,
    )
    assert len(deterministic) == 1
    assert "validate_node_test_policy.py" in deterministic[0][2]
    assert "pnpm" not in deterministic[0]
    security = module.plan("node", tmp_path, lane="security", platform_root=platform)
    assert "secret_scan.py" in security[0][1]
    assert len(security) == 1
    assert all("corepack" not in command and "pnpm" not in command for command in security)


def test_powershell_profile_uses_pwsh_and_pester_not_pytest(tmp_path: Path) -> None:
    """Catches a PowerShell repository being routed through Python policy tooling."""
    module = load_runner()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "Example.Tests.ps1").write_text("Describe 'x' {}", encoding="utf-8")

    assert module.plan("powershell", tmp_path) == []


def test_node_profile_ignores_package_script_but_rejects_unpinned_manager(tmp_path: Path) -> None:
    """Catches target package scripts becoming commands instead of the protected-base manifest."""
    module = load_runner()
    platform = tmp_path / "platform"
    write_security_platform(platform)
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    for package in ({"scripts": {"test": "node --test"}}, {"packageManager": "npm@latest"}):
        (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
        with pytest.raises(ValueError):
            module.plan("node", tmp_path, platform_root=platform, base_sha="a" * 40)
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.9.2", "scripts": {"test": "node --test --test-only"}}),
        encoding="utf-8",
    )
    command = module.plan("node", tmp_path, platform_root=platform, base_sha="a" * 40)[0]
    assert "test-only" not in command


def test_profile_runner_executes_only_allowlisted_native_commands_and_verifies_versions(tmp_path: Path) -> None:
    """Catches trusted deterministic routing executing target-owned Node package scripts."""
    module = load_runner()
    platform = tmp_path / "platform"
    write_security_platform(platform)
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.9.2", "scripts": {"test": "node --test"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    commands: list[list[str]] = []

    def runner(command: list[str], *, cwd: Path, capture_output: bool) -> str:
        assert cwd == tmp_path
        commands.append(command)
        if command == ["node", "--version"]:
            return "v22.14.0\n"
        if command == ["npm", "--version"]:
            return "10.9.2\n"
        return ""

    module.execute(
        "node",
        tmp_path,
        platform_root=platform,
        base_sha="a" * 40,
        runner=runner,
    )

    assert len(commands) == 1
    assert "validate_node_test_policy.py" in commands[0][2]
    assert all("pytest" not in command and "coverage" not in command for command in commands)
    assert all("npm" not in command and "node" not in command for command in commands)


def test_profile_runner_never_runs_target_node_tooling_on_host(tmp_path: Path) -> None:
    """Catches the static host lane executing target package managers or dependency code."""
    module = load_runner()
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.9.2", "scripts": {"test": "node --test"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    platform = tmp_path / "platform"
    write_security_platform(platform)

    commands: list[list[str]] = []

    def runner(command: list[str], *, cwd: Path, capture_output: bool) -> str:
        del capture_output
        assert cwd == tmp_path
        commands.append(command)
        return ""

    module.execute("node", tmp_path, lane="security", platform_root=platform, runner=runner)
    assert len(commands) == 1
    assert "secret_scan.py" in commands[0][1]
    assert all(command[0] not in {"corepack", "node", "npm", "pnpm", "yarn"} for command in commands)


def test_profile_runner_executes_pinned_pester_and_no_python_lane(tmp_path: Path) -> None:
    """Catches trusted host execution importing target PowerShell tests before isolation."""
    module = load_runner()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "Example.Tests.ps1").write_text("Describe 'x' {}", encoding="utf-8")
    commands: list[list[str]] = []

    def runner(command: list[str], *, cwd: Path, capture_output: bool) -> str:
        assert cwd == tmp_path
        commands.append(command)
        return "5.7.1\n" if capture_output else ""

    module.execute("powershell", tmp_path, runner=runner)

    assert commands == []


@pytest.mark.parametrize("profile", ["python", "critical-ml"])
def test_python_profiles_execute_closed_static_security_and_coverage_commands(tmp_path: Path, profile: str) -> None:
    """Catches target dependencies entering the trusted interpreter or static policy being PR-owned."""
    module = load_runner()
    platform = tmp_path / "platform"
    target = tmp_path / "target"
    platform.mkdir()
    target.mkdir()
    write_security_platform(platform)
    (platform / "requirements-dev.txt").write_text(PINNED_REQUIREMENTS, encoding="utf-8")
    (platform / "scripts").mkdir(exist_ok=True)
    for script in ("run_test_policy.py", "evaluate_coverage.py", "validate_test_policy_manifest.py"):
        (platform / "scripts" / script).write_text("", encoding="utf-8")
    (target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    (target / "src").mkdir()
    (target / "src" / "example.py").write_text("value: int = 1\n", encoding="utf-8")
    (target / ".github").mkdir()
    (target / ".github" / "ci-platform-test-policy.json").write_text(
        json.dumps(
            {
                "critical_tests": {
                    category: [f"tests/{category}/test_hook.py"]
                    for category in ("leakage", "lineage", "model", "parity", "schema")
                }
            }
        ),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def runner(command: list[str], *, cwd: Path, capture_output: bool) -> str:
        del capture_output
        assert cwd == target
        commands.append(command)
        return ""

    deterministic_options: dict[str, object] = {}
    if profile == "critical-ml":
        deterministic_options = {"base_sha": "a" * 40, "evidence_dir": tmp_path / "deterministic-evidence"}
    module.execute(
        profile,
        target,
        lane="deterministic",
        platform_root=platform,
        runner=runner,
        **deterministic_options,
    )
    serialized = ["\0".join(command) for command in commands]
    assert not any("\0pip\0install" in command or "\0pip\0check" in command for command in serialized)
    assert any("run_module_isolated.py" in command and "\0ruff\0" in command for command in serialized)
    assert all("-I\0-S" in command for command in serialized if "run_module_isolated.py" in command)
    assert any(str(platform / "contract" / "ruff-v1.toml") in command for command in commands)
    assert not any("\0mypy\0" in command for command in serialized)
    if profile == "critical-ml":
        assert any("validate_test_policy_manifest.py" in part for command in commands for part in command)
    assert not any(part == "pytest" or part.endswith("pytest.py") for command in commands for part in command)

    commands.clear()
    module.execute(profile, target, lane="security", platform_root=platform, runner=runner)
    assert any("secret_scan.py" in part for command in commands for part in command)
    assert any(
        any("run_module_isolated.py" in part for part in command) and "bandit" in command for command in commands
    )
    assert not any("pip_audit" in command or "\0pip\0" in command for command in map("\0".join, commands))

    commands.clear()
    module.execute(
        profile,
        target,
        lane="coverage",
        platform_root=platform,
        base_sha="a" * 40,
        head_sha="b" * 40,
        evidence_dir=tmp_path / "evidence",
        target_site=tmp_path,
        runner=runner,
    )
    assert any("run_test_policy.py" in part for command in commands for part in command)
    assert not any("evaluate_coverage.py" in part for command in commands for part in command)


def test_critical_ml_cannot_downgrade_to_ordinary_python_without_protected_hooks(tmp_path: Path) -> None:
    """Catches a critical-ML repository inheriting ordinary Python behavior without safety hooks."""
    module = load_runner()
    platform = tmp_path / "platform"
    target = tmp_path / "target"
    platform.mkdir()
    target.mkdir()
    write_security_platform(platform)
    (platform / "requirements-dev.txt").write_text(PINNED_REQUIREMENTS, encoding="utf-8")
    (platform / "scripts" / "run_test_policy.py").write_text("", encoding="utf-8")
    (platform / "scripts" / "validate_test_policy_manifest.py").write_text("", encoding="utf-8")
    (target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="critical-ml"):
        module.plan(
            "critical-ml",
            target,
            platform_root=platform,
            base_sha="a" * 40,
            evidence_dir=tmp_path / "evidence",
        )


@pytest.mark.parametrize("profile", ["python", "critical-ml"])
def test_python_test_policy_executes_only_once_in_coverage_lane(tmp_path: Path, profile: str) -> None:
    """Catches deterministic and coverage both running the full protected test suite."""
    module = load_runner()
    platform = tmp_path / "platform"
    target = tmp_path / "target"
    platform.mkdir()
    target.mkdir()
    write_security_platform(platform)
    (platform / "requirements-dev.txt").write_text(PINNED_REQUIREMENTS, encoding="utf-8")
    for name in ("run_test_policy.py", "evaluate_coverage.py", "validate_test_policy_manifest.py"):
        (platform / "scripts" / name).write_text("", encoding="utf-8")
    (target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    (target / ".github").mkdir()
    (target / ".github" / "ci-platform-test-policy.json").write_text(
        json.dumps(
            {
                "critical_tests": {
                    category: [f"tests/{category}/test_hook.py"]
                    for category in ("leakage", "lineage", "model", "parity", "schema")
                }
            }
        ),
        encoding="utf-8",
    )
    deterministic = module.plan(
        profile,
        target,
        platform_root=platform,
        base_sha="a" * 40,
        evidence_dir=tmp_path / "deterministic",
    )
    coverage = module.plan(
        profile,
        target,
        lane="coverage",
        platform_root=platform,
        base_sha="a" * 40,
        head_sha="b" * 40,
        evidence_dir=tmp_path / "coverage",
        target_site=tmp_path,
    )
    combined = deterministic + coverage
    assert sum("run_test_policy.py" in part for command in combined for part in command) == 1
    assert not any(command[1:4] == ["-I", "-m", "pytest"] for command in deterministic)


def test_python_tool_modules_are_isolated_from_untrusted_target_shadowing(tmp_path: Path) -> None:
    """Catches target-local modules replacing pip, Ruff, mypy, audit, Bandit, or pytest."""
    module = load_runner()
    platform = tmp_path / "platform"
    target = tmp_path / "target"
    platform.mkdir()
    target.mkdir()
    write_security_platform(platform)
    (platform / "requirements-dev.txt").write_text(PINNED_REQUIREMENTS, encoding="utf-8")
    for name in ("run_test_policy.py", "evaluate_coverage.py"):
        (platform / "scripts" / name).write_text("", encoding="utf-8")
    (target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    for name in ("ruff.py", "mypy.py", "pip_audit.py", "bandit.py", "pytest.py"):
        (target / name).write_text("raise SystemExit(0)\n", encoding="utf-8")
    (target / "pip").mkdir()
    (target / "pip" / "__main__.py").write_text("raise SystemExit(0)\n", encoding="utf-8")

    commands = module.plan("python", target, platform_root=platform)
    commands += module.plan("python", target, lane="security", platform_root=platform)
    module_commands = [command for command in commands if any("run_module_isolated.py" in part for part in command)]

    assert module_commands
    assert all(command[:3] == [module.sys.executable, "-I", "-S"] for command in module_commands)
    assert all(str(target) not in command[: command.index("--") + 1] for command in module_commands)


def test_pr_owned_ruff_config_cannot_hide_host_static_findings(tmp_path: Path) -> None:
    """Catches PR pyproject excludes weakening immutable host-side Ruff policy."""
    module = load_runner()
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text("", encoding="utf-8")
    (target / "bad.py").write_text(
        "def broken(value: int) -> str:\n    return missing_name\n",
        encoding="utf-8",
    )
    (target / "pyproject.toml").write_text(
        '[tool.ruff]\nexclude = ["bad.py"]\n[tool.mypy]\nexclude = "bad.py"\n',
        encoding="utf-8",
    )
    commands = module.plan("python", target, platform_root=ROOT)
    ruff = next(command for command in commands if "ruff" in command)

    ruff_result = module.subprocess.run(ruff, cwd=target, check=False, capture_output=True, text=True)

    assert ruff_result.returncode != 0
    assert "bad.py" in ruff_result.stdout + ruff_result.stderr
    assert all("mypy" not in command for command in commands)


def test_pr_owned_bandit_config_cannot_hide_host_security_findings(tmp_path: Path) -> None:
    """Catches candidate .bandit auto-discovery suppressing an immutable security check."""
    module = load_runner()
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text("", encoding="utf-8")
    (target / "bad.py").write_text(
        "def execute(user_input: str) -> object:\n    return eval(user_input)\n",
        encoding="utf-8",
    )
    (target / ".bandit").write_text("[bandit]\nskips = B307\n", encoding="utf-8")
    commands = module.plan("python", target, lane="security", platform_root=ROOT)
    bandit = next(command for command in commands if "bandit" in command)

    result = module.subprocess.run(bandit, cwd=target, check=False, capture_output=True, text=True)

    assert result.returncode != 0
    assert "B307" in result.stdout + result.stderr
    assert "--ini" in bandit
    assert str(ROOT / "contract" / "bandit-v1.ini") in bandit


@pytest.mark.parametrize("profile", ["baseline", "python", "node", "powershell", "critical-ml"])
def test_every_profile_security_lane_includes_common_pinned_secret_scan(tmp_path: Path, profile: str) -> None:
    """Catches baseline or PowerShell bypassing the all-repository secret floor."""
    module = load_runner()
    platform = tmp_path / "platform"
    target = tmp_path / "target"
    platform.mkdir()
    target.mkdir()
    write_security_platform(platform)
    if profile in {"python", "critical-ml"}:
        (platform / "requirements-dev.txt").write_text(PINNED_REQUIREMENTS, encoding="utf-8")
        (target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    if profile == "node":
        (target / "package.json").write_text(
            json.dumps({"packageManager": "npm@10.9.2", "scripts": {"test": "node --test"}}),
            encoding="utf-8",
        )
        (target / "package-lock.json").write_text("{}", encoding="utf-8")
    commands = module.plan(profile, target, lane="security", platform_root=platform)
    assert "secret_scan.py" in commands[0][1]


def test_baseline_profile_executes_structural_validation_and_rejects_malformed_data(tmp_path: Path) -> None:
    """Catches the baseline profile being an unconditional failure or empty synthetic pass."""
    module = load_runner()
    (tmp_path / "config.json").write_text('{"ok": true}\n', encoding="utf-8")
    module.execute("baseline", tmp_path, lane="deterministic", runner=lambda *args, **kwargs: "")
    (tmp_path / "config.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match=r"config\.json"):
        module.execute("baseline", tmp_path, lane="deterministic", runner=lambda *args, **kwargs: "")
