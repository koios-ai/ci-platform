from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_isolated_runtime.py"
VERIFY = ROOT / "scripts" / "verify_runtime_evidence.py"
PROFILE_RUNNER = ROOT / "scripts" / "profile_runner.py"
CONSUMER_PRE_V1 = ROOT / "tests" / "fixtures" / "consumer-pre-v1"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_container_plan_has_closed_security_boundary(tmp_path: Path) -> None:
    """Catches target code escaping onto the runner or receiving host control channels."""
    module = load_module(RUNTIME, "runtime_isolation_plan")
    target = tmp_path / "target"
    evidence = tmp_path / "evidence"
    dependencies = tmp_path / "deps"
    for path in (target, evidence, dependencies):
        path.mkdir()

    command = module.container_command(
        image=module.PYTHON_RUNTIME_IMAGE,
        target=target,
        evidence=evidence,
        dependencies=dependencies,
        network="none",
        arguments=["python", "tests"],
    )
    joined = "\0".join(command)
    nul = "\0"
    assert command[:3] == ["docker", "run", "--rm"]
    for required in (
        "--read-only",
        f"--user{nul}65532:65532",
        "--cap-drop\0ALL",
        "--security-opt\0no-new-privileges:true",
        f"--pids-limit{nul}256",
        f"--memory{nul}4g",
        f"--cpus{nul}2",
        "--network\0none",
        "--tmpfs\0/tmp:rw,noexec,nosuid,size=536870912",
    ):
        assert required in joined
    assert f"src={target.resolve()},dst=/workspace/target,readonly" in joined
    assert f"src={dependencies.resolve()},dst=/workspace/dependencies,readonly" in joined
    assert f"src={evidence.resolve()},dst=/workspace/runtime-output" in joined
    assert "/workspace/evidence" not in joined
    assert "/var/run/docker.sock" not in joined
    assert not any(
        name in joined
        for name in (
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "GITHUB_PATH",
            "GITHUB_STEP_SUMMARY",
            "GITHUB_TOKEN",
        )
    )


@pytest.mark.parametrize("link_value", ["../../runner-secret.txt", "C:/runner-secret.txt"])
def test_host_target_readers_reject_relative_and_absolute_tracked_symlinks(
    tmp_path: Path,
    link_value: str,
) -> None:
    """Catches a Git symlink copying runner files into a networked container or host parser."""
    runtime = load_module(RUNTIME, f"runtime_gitlink_{hashlib.sha256(link_value.encode()).hexdigest()[:8]}")
    profile = load_module(PROFILE_RUNNER, f"profile_gitlink_{hashlib.sha256(link_value.encode()).hexdigest()[:8]}")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    object_id = subprocess.check_output(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=tmp_path,
        input=link_value,
        text=True,
    ).strip()
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", "120000", object_id, "requirements.txt"],
        cwd=tmp_path,
        check=True,
    )

    with pytest.raises(ValueError, match="non-regular"):
        runtime._reject_nonregular_tracked_entries(tmp_path)
    with pytest.raises(ValueError, match="non-regular"):
        profile._reject_nonregular_tracked_entries(tmp_path)


def test_python_runtime_plan_separates_networked_build_from_networkless_tests(tmp_path: Path) -> None:
    """Catches target dependency hooks sharing the evidence or trusted test container."""
    module = load_module(RUNTIME, "runtime_python_plan")
    target = tmp_path / "target"
    platform = tmp_path / "platform"
    evidence = tmp_path / "evidence"
    for path in (target, platform, evidence):
        path.mkdir()
    (target / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    protected_manifest = tmp_path / "protected-python-base.json"
    protected_manifest.write_text("{}\n", encoding="utf-8")

    plan = module.python_runtime_plan(
        target=target,
        platform=platform,
        evidence=evidence,
        protected_base_manifest=protected_manifest,
        profile="python",
        base_sha="a" * 40,
        head_sha="b" * 40,
    )
    networked = [command for command in plan if "--network\0bridge" in "\0".join(command)]
    assert len(networked) == 2
    for command in networked:
        raw = "\0".join(command)
        assert "/workspace/runtime-output" not in raw
        assert f"src={target.resolve()},dst=/workspace/target" not in raw
    dependency = next(command for command in networked if "\0pip\0install\0" in "\0".join(command))
    audit = next(command for command in networked if "\0pip_audit\0" in "\0".join(command))
    assert "/workspace/target/requirements.txt" in dependency
    assert "/workspace/target/requirements.txt" in audit

    typing = next(command for command in plan if "\0mypy\0" in "\0".join(command))
    test = plan[-1]
    assert "--network\0none" in "\0".join(typing)
    assert "--network\0none" in "\0".join(test)
    assert "MYPYPATH=/workspace/target-site" in typing
    assert "/opt/ci-platform/contract/mypy-v1.ini" in typing
    assert "--cache-dir\0/tmp/mypy-cache" in "\0".join(typing)
    assert f"src={target.resolve()},dst=/workspace/target,readonly" in "\0".join(typing)
    assert "target-site" in "\0".join(dependency)
    assert "target-site" in "\0".join(typing)
    assert "target-site" in "\0".join(test)
    assert "--trusted-site\0/opt/ci-platform-venv/lib/python3.12/site-packages" in "\0".join(test)
    assert "--protected-pytest-config\0/opt/ci-platform/contract/pytest-v1.ini" in "\0".join(test)
    assert "--protected-base-manifest\0/workspace/protected-python-base.json" in "\0".join(test)
    assert f"src={protected_manifest.resolve()},dst=/workspace/protected-python-base.json,readonly" in "\0".join(test)
    assert "\0git\0" not in "\0".join(test)
    image_index = test.index(module.PYTHON_RUNTIME_IMAGE)
    assert test[image_index + 1 : image_index + 3] == ["-I", "-S"]


@pytest.mark.parametrize(
    "requirement",
    [
        "project @ https://example.invalid/project.whl\n",
        "git+https://example.invalid/repo.git\n",
        "-e ../local\n",
        "./local-package\n",
        "unbounded>=1\n",
    ],
)
def test_python_networked_fetch_rejects_url_vcs_local_and_unpinned_dependencies(
    tmp_path: Path, requirement: str
) -> None:
    module = load_module(RUNTIME, f"runtime_manifest_{hashlib.sha256(requirement.encode()).hexdigest()[:8]}")
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text(requirement, encoding="utf-8")
    with pytest.raises(ValueError, match="closed exact registry pin"):
        module.python_runtime_plan(
            target=target,
            platform=tmp_path,
            evidence=tmp_path / "evidence",
            protected_base_manifest=tmp_path / "unused-protected-base.json",
            profile="python",
            base_sha="a" * 40,
            head_sha="b" * 40,
        )


def test_generic_pre_v1_dependency_graph_remains_a_named_migration_blocker(
    tmp_path: Path,
) -> None:
    """Catches silently relaxing the closed network manifest boundary for a legacy consumer graph."""
    module = load_module(RUNTIME, "runtime_consumer_manifest_migration")
    with pytest.raises(ValueError, match="closed exact registry pin"):
        module._stage_python_manifests(CONSUMER_PRE_V1, tmp_path / "staged")
    contract = json.loads((ROOT / "contract" / "v1.json").read_text(encoding="utf-8"))
    assert "first-critical-consumer-python-manifest-v1-migration" in contract["x-merge-gate-v1"]["release_blockers"]


def test_pester_profile_is_blocked_until_the_module_artifact_is_digest_bound(tmp_path: Path) -> None:
    """Catches a mutable PSGallery download entering an otherwise pinned runtime."""
    module = load_module(RUNTIME, "runtime_pester_network_boundary")
    target = tmp_path / "target"
    platform = tmp_path / "platform"
    target.mkdir()
    platform.mkdir()
    (target / "tests").mkdir()
    (target / "tests" / "Example.Tests.ps1").write_text("Describe 'x' {}", encoding="utf-8")
    with pytest.raises(ValueError, match="digest-bound Pester"):
        module.powershell_runtime_plan(
            target=target,
            platform=platform,
            evidence=tmp_path / "evidence",
        )


def test_networked_yarn_build_rejects_candidate_registry_or_plugin_configuration(
    tmp_path: Path,
) -> None:
    """Catches target-controlled Yarn configuration entering the networked dependency container."""
    module = load_module(RUNTIME, "runtime_yarn_network_boundary")
    target = tmp_path / "target"
    target.mkdir()
    (target / "package.json").write_text(
        json.dumps({"packageManager": "yarn@4.7.0"}),
        encoding="utf-8",
    )
    (target / "yarn.lock").write_text(
        "__metadata:\n  version: 8\n",
        encoding="utf-8",
    )
    (target / ".yarnrc.yml").write_text(
        'npmRegistryServer: "https://attacker.invalid"\nplugins:\n  - path: ./attacker.cjs\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="candidate Yarn configuration"):
        module._materialize_node_build(target, tmp_path / "rejected-build", "yarn.lock")

    (target / ".yarnrc.yml").unlink()
    build = tmp_path / "node-build"
    module._materialize_node_build(target, build, "yarn.lock")
    synthesized = (build / ".yarnrc.yml").read_text(encoding="utf-8")
    assert "https://registry.npmjs.org" in synthesized
    assert "enableScripts: false" in synthesized
    assert "nodeLinker: node-modules" in synthesized
    assert "attacker.invalid" not in synthesized
    assert "plugins:" not in synthesized


@pytest.mark.parametrize(
    "declaration",
    [
        {"dependencies": {"left-pad": "owner/repository"}},
        {"dependencies": {"left-pad": "github:owner/repository"}},
        {"dependencies": {"left-pad": "npm:@scope/pkg@github:owner/repository"}},
        {"overrides": {"left-pad": "owner/repository"}},
        {"resolutions": {"left-pad": "https://attacker.invalid/archive.tgz"}},
        {"pnpm": {"overrides": {"left-pad": "git+ssh://git@github.com/owner/repository"}}},
    ],
)
def test_node_manifest_rejects_github_shorthand_and_non_registry_override_specs(
    tmp_path: Path,
    declaration: dict[str, Any],
) -> None:
    """Catches dependency and override sources that bypass the npm registry boundary."""
    module = load_module(RUNTIME, f"runtime_node_manifest_{hashlib.sha256(repr(declaration).encode()).hexdigest()[:8]}")
    target = tmp_path / "target"
    target.mkdir()
    package = {"packageManager": "npm@10.9.2", **declaration}
    (target / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (target / "package-lock.json").write_text(
        json.dumps({"name": "fixture", "lockfileVersion": 3, "packages": {"": {}}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="registry"):
        module._node_configuration(target)


@pytest.mark.parametrize(
    ("lock_name", "lock_value"),
    [
        (
            "package-lock.json",
            json.dumps(
                {
                    "name": "fixture",
                    "lockfileVersion": 3,
                    "packages": {"": {}, "node_modules/pkg": {"version": "owner/repository"}},
                }
            ),
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\noverrides:\n  pkg: owner/repository\n",
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\noverrides: {pkg: owner/repository}\n",
        ),
        (
            "yarn.lock",
            '__metadata:\n  version: 8\n"pkg@npm:^1.0.0":\n  resolution: "pkg@github:owner/repository"\n',
        ),
        (
            "yarn.lock",
            '__metadata:\n  version: 8\n"pkg@npm:^1.0.0":\n  resolution: "pkg@owner/repository"\n',
        ),
    ],
)
def test_node_lock_rejects_non_registry_versions_and_overrides(
    tmp_path: Path,
    lock_name: str,
    lock_value: str,
) -> None:
    """Catches lockfile entries that resolve outside the npm registry despite a safe manifest."""
    module = load_module(RUNTIME, f"runtime_node_lock_{lock_name.replace('.', '_')}")
    target = tmp_path / "target"
    target.mkdir()
    (target / lock_name).write_text(lock_value, encoding="utf-8")

    with pytest.raises(ValueError, match="non-registry"):
        module._validate_node_lock(target, lock_name)


@pytest.mark.parametrize(
    "mutation",
    [
        {"lockfileVersion": 2, "packages": {"": {}}},
        {"lockfileVersion": 3},
        {"lockfileVersion": 3, "packages": {"": {}}, "unknown": "accepted-by-npm"},
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/pkg": {
                    "version": "1.0.0",
                    "from": "github:owner/repository",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 86 + "==",
                },
            },
        },
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 85 + "B" + "==",
                },
            },
        },
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                },
            },
        },
    ],
)
def test_active_npm_lock_requires_closed_v3_registry_artifacts(
    tmp_path: Path,
    mutation: dict[str, Any],
) -> None:
    """Catches npm-ci inputs whose source or bytes are not registry and SRI bound."""
    module = load_module(RUNTIME, f"runtime_npm_lock_closed_{hashlib.sha256(repr(mutation).encode()).hexdigest()[:8]}")
    target = tmp_path / "target"
    target.mkdir()
    (target / "package-lock.json").write_text(json.dumps(mutation), encoding="utf-8")

    with pytest.raises(ValueError, match=r"lockfile|schema|integrity|non-registry"):
        module._validate_node_lock(target, "package-lock.json")


def test_active_npm_lock_accepts_registry_resolution_with_sha512_integrity(tmp_path: Path) -> None:
    """Pins the supported npm lock subset used before the networked npm-ci step."""
    module = load_module(RUNTIME, "runtime_npm_lock_valid_registry")
    target = tmp_path / "target"
    target.mkdir()
    (target / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/pkg": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                        "integrity": "sha512-" + "A" * 86 + "==",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    module._validate_node_lock(target, "package-lock.json")


def test_sha512_sri_requires_canonical_base64_padding_bits() -> None:
    """Catches syntactically valid Base64 whose discarded padding bits are nonzero."""
    module = load_module(RUNTIME, "runtime_sha512_sri_canonical")

    assert module._is_canonical_sha512_sri("sha512-" + "A" * 86 + "==")
    assert not module._is_canonical_sha512_sri("sha512-" + "A" * 85 + "B" + "==")


def test_node_audit_covers_production_and_development_dependencies_at_lowest_severity() -> None:
    """Catches omitted dev dependencies or severity thresholds that tolerate known vulnerabilities."""
    module = load_module(RUNTIME, "runtime_node_audit_commands")
    commands = {manager: module._node_audit_command(manager) for manager in module.NODE_MANAGERS}

    npm = "\0".join(commands["npm"])
    assert "--omit=dev" not in npm
    assert "--include=prod" in npm
    assert "--include=dev" in npm
    assert "--audit-level=low" in npm

    pnpm = "\0".join(commands["pnpm"])
    assert "--prod" not in pnpm
    assert "--audit-level=low" in pnpm

    yarn = "\0".join(commands["yarn"])
    assert "--all" in yarn
    assert "--recursive" in yarn
    assert "--severity=low" in yarn


@pytest.mark.parametrize("manager", ["pnpm", "yarn"])
def test_corepack_managers_are_blocked_until_their_artifacts_are_digest_bound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    manager: str,
) -> None:
    """Catches runtime Corepack downloads selected by version without immutable package integrity."""
    module = load_module(RUNTIME, f"runtime_corepack_block_{manager}")
    target = tmp_path / "target"
    platform = tmp_path / "platform"
    target.mkdir()
    platform.mkdir()
    lock = {"pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}[manager]
    (target / "package.json").write_text(
        json.dumps({"packageManager": f"{manager}@{module.NODE_MANAGERS[manager]}"}),
        encoding="utf-8",
    )
    (target / lock).write_text("lockfileVersion: '9.0'\n" if manager == "pnpm" else "__metadata:\n  version: 8\n")
    fake_verifier = type(
        "Verifier",
        (),
        {"load_node_policy_from_base": staticmethod(lambda _target, _base: {"version": 1})},
    )
    monkeypatch.setattr(module, "_verifier_module", lambda: fake_verifier)

    with pytest.raises(ValueError, match="digest-bound"):
        module.node_runtime_plan(
            target=target,
            platform=platform,
            evidence=tmp_path / "evidence",
            base_sha="a" * 40,
        )


def test_npm_runtime_plan_verifies_the_image_bound_manager_before_network_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches a pinned Node image silently exposing a different npm toolchain."""
    module = load_module(RUNTIME, "runtime_npm_manager_attestation")
    target = tmp_path / "target"
    platform = tmp_path / "platform"
    target.mkdir()
    platform.mkdir()
    (target / "package.json").write_text(json.dumps({"packageManager": "npm@10.9.2"}), encoding="utf-8")
    (target / "package-lock.json").write_text(
        json.dumps({"name": "fixture", "lockfileVersion": 3, "packages": {"": {}}}),
        encoding="utf-8",
    )
    policy = {
        "version": 1,
        "adapter": "node-test",
        "test_files": ["tests/example.test.mjs"],
        "unexpected_skip_policy": "fail",
    }
    fake_verifier = type("Verifier", (), {"load_node_policy_from_base": staticmethod(lambda _target, _base: policy)})
    monkeypatch.setattr(module, "_verifier_module", lambda: fake_verifier)

    plan, _ = module.node_runtime_plan(
        target=target,
        platform=platform,
        evidence=tmp_path / "evidence",
        base_sha="a" * 40,
    )
    verification = plan[0]
    assert "--network\0none" in "\0".join(verification)
    assert module.NODE_RUNTIME_IMAGE in verification
    assert module.NODE_MANAGERS["npm"] in "\0".join(verification)
    assert "npm/package.json" in "\0".join(verification)
    assert "--network\0bridge" in "\0".join(plan[1])


def test_docker_context_is_an_exact_runtime_input_allowlist() -> None:
    """Catches an unexpected credential, fixture, or checkout file entering the build context."""
    ignore = ROOT / ".dockerignore"
    assert ignore.is_file()
    patterns = {
        line.strip()
        for line in ignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "**" in patterns
    allowed = {
        "!docker/",
        "!docker/ci-python-runtime.Dockerfile",
        "!requirements-dev.txt",
        "!contract/",
        "!contract/coverage-v1.ini",
        "!contract/mypy-v1.ini",
        "!contract/pytest-v1.ini",
        "!scripts/",
        "!scripts/run_module_isolated.py",
        "!scripts/run_platform_script.py",
        "!scripts/run_pytest_isolated.py",
        "!scripts/run_test_policy.py",
        "!scripts/test_policy.py",
    }
    assert {item for item in patterns if item.startswith("!")} == allowed
    assert all(not item.startswith("!.") for item in allowed)

    dockerfile = (ROOT / "docker" / "ci-python-runtime.Dockerfile").read_text(encoding="utf-8")
    assert "COPY contract /" not in dockerfile
    assert "COPY scripts /" not in dockerfile
    for relative in ("coverage-v1.ini", "mypy-v1.ini", "pytest-v1.ini"):
        assert f"contract/{relative}" in dockerfile
    for relative in (
        "run_module_isolated.py",
        "run_platform_script.py",
        "run_pytest_isolated.py",
        "run_test_policy.py",
        "test_policy.py",
    ):
        assert f"scripts/{relative}" in dockerfile


def test_fresh_verifier_rejects_zero_skipped_or_unallowlisted_python_evidence(tmp_path: Path) -> None:
    """Catches a runtime job uploading a synthetic or surplus evidence bundle."""
    module = load_module(VERIFY, "runtime_evidence_verifier")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in module.PYTHON_EVIDENCE_FILES:
        (evidence / name).write_text("{}\n", encoding="utf-8")
    (evidence / "pytest-junit.xml").write_text(
        '<testsuites tests="0" failures="0" errors="0" skipped="0"/>\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="zero"):
        module.verify_python_evidence(evidence, profile="python", base_sha="a" * 40)

    (evidence / "unexpected.txt").write_text("surplus\n", encoding="utf-8")
    with pytest.raises(ValueError, match="allowlist"):
        module.validate_bundle(evidence, module.PYTHON_EVIDENCE_FILES)


@pytest.mark.parametrize(
    ("allowlist_name", "relative"),
    [
        ("python", "pytest-junit.xml"),
        ("node", "node-test.tap"),
        ("powershell", "pester-results.xml"),
    ],
)
def test_runtime_evidence_rejects_profile_payload_symlinks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    allowlist_name: str,
    relative: str,
) -> None:
    """Catches target-owned evidence links disclosing runner files during verification or promotion."""
    module = load_module(VERIFY, f"runtime_evidence_link_{allowlist_name}")
    outside = tmp_path / "runner-secret.txt"
    outside.write_text("host-only\n", encoding="utf-8")
    evidence = tmp_path / allowlist_name
    evidence.mkdir()
    linked = evidence / relative
    linked.write_text("simulated-link-payload\n", encoding="utf-8")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == linked or original_is_symlink(self),
    )
    allowlist = {
        "python": module.PYTHON_EVIDENCE_FILES,
        "node": module.NODE_EVIDENCE_FILES,
        "powershell": module.POWERSHELL_EVIDENCE_FILES,
    }[allowlist_name]

    with pytest.raises(ValueError, match="non-regular"):
        module.validate_bundle(evidence, allowlist)


def test_node_policy_is_protected_base_declarative_and_every_file_must_pass(tmp_path: Path) -> None:
    """Catches package scripts, selectors, zero tests, skips, or partial file execution."""
    module = load_module(VERIFY, "node_evidence_verifier")
    policy = {
        "version": 1,
        "adapter": "node-test",
        "test_files": ["tests/a.test.mjs", "tests/b.test.js"],
        "unexpected_skip_policy": "fail",
    }
    validated = module.validate_node_policy(policy)
    assert validated["test_files"] == policy["test_files"]
    for invalid in (
        {**policy, "command": "node --test --test-only"},
        {**policy, "test_files": []},
        {**policy, "test_files": ["--test-name-pattern=x"]},
        {**policy, "test_files": ["tests/*.js"]},
    ):
        with pytest.raises(ValueError):
            module.validate_node_policy(invalid)

    evidence = tmp_path / "node"
    evidence.mkdir()
    summary: dict[str, Any] = {
        "schema_version": 1,
        "adapter": "node-test",
        "test_files": policy["test_files"],
        "totals": {"tests": 2, "passed": 2, "failed": 0, "skipped": 0, "todo": 0},
        "per_file": {
            "tests/a.test.mjs": {"tests": 1, "passed": 1, "failed": 0, "skipped": 0, "todo": 0},
            "tests/b.test.js": {"tests": 1, "passed": 1, "failed": 0, "skipped": 0, "todo": 0},
        },
        "status": "passed",
    }
    (evidence / "node-test-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (evidence / "node-test.tap").write_text(
        "### tests/a.test.mjs\nTAP version 13\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# todo 0\n"
        "### tests/b.test.js\nTAP version 13\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# todo 0\n",
        encoding="utf-8",
    )
    module.verify_node_evidence(evidence, policy)
    summary["per_file"].pop("tests/b.test.js")
    (evidence / "node-test-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(ValueError, match="every declared"):
        module.verify_node_evidence(evidence, policy)


def test_runtime_attestation_binds_payload_and_all_execution_provenance(tmp_path: Path) -> None:
    """Catches replay across head/platform/attempt or post-capture evidence mutation."""
    module = load_module(VERIFY, "runtime_attestation_verifier")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    payload = b"proof\n"
    (evidence / "proof.txt").write_bytes(payload)
    context = {
        "profile": "python",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "platform_sha": "c" * 40,
        "workflow_attempt": 3,
        "policy_digest": "d" * 64,
    }
    attestation = {
        "schema_version": 1,
        "status": "captured-after-target-exit",
        **context,
        "image_digest": "sha256:" + "e" * 64,
        "evidence_sha256": {"proof.txt": hashlib.sha256(payload).hexdigest()},
    }
    (evidence / "runtime-attestation.json").write_text(json.dumps(attestation), encoding="utf-8")
    module.verify_attestation(evidence, {"proof.txt"}, **context)

    candidate = dict(attestation)
    candidate["head_sha"] = "f" * 40
    (evidence / "runtime-attestation.json").write_text(json.dumps(candidate), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance"):
        module.verify_attestation(evidence, {"proof.txt"}, **context)

    (evidence / "runtime-attestation.json").write_text(json.dumps(attestation), encoding="utf-8")
    (evidence / "proof.txt").write_text("mutated\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        module.verify_attestation(evidence, {"proof.txt"}, **context)
