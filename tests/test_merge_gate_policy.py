from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "merge_gate_policy.py"
PLATFORM_SHA = "a" * 40
HEAD_SHA = "b" * 40
BASE_SHA = "c" * 40
DEPENDABOT_USER = {
    "login": "dependabot[bot]",
    "id": 49699333,
    "node_id": "MDM6Qm90NDk2OTkzMzM=",
    "type": "Bot",
}
PROFILE_WORKFLOWS = {
    "baseline": "merge-gate-v1.yml",
    "python": "merge-gate-python-v1.yml",
    "node": "merge-gate-node-v1.yml",
    "powershell": "merge-gate-powershell-v1.yml",
    "critical-ml": "merge-gate-critical-ml-v1.yml",
}


def load_policy() -> ModuleType:
    spec = importlib.util.spec_from_file_location("merge_gate_policy", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pull_request_context(**overrides: object) -> dict[str, object]:
    profile = str(overrides.get("default_profile", "node"))
    workflow_path = PROFILE_WORKFLOWS[profile]
    value: dict[str, object] = {
        "event_name": "pull_request",
        "event": {
            "action": "synchronize",
            "pull_request": {
                "number": 17,
                "draft": False,
                "base": {"sha": BASE_SHA},
                "head": {"sha": HEAD_SHA, "repo": {"id": 123, "full_name": "koios-ai/example"}},
                "user": {"login": "contributor", "id": 7, "node_id": "user-node", "type": "User"},
            },
            "repository": {"id": 123, "full_name": "koios-ai/example"},
            "sender": {"login": "contributor"},
        },
        "workflow_repository": "koios-ai/ci-platform",
        "workflow_sha": PLATFORM_SHA,
        "workflow_ref": f"koios-ai/ci-platform/.github/workflows/{workflow_path}@{PLATFORM_SHA}",
        "workflow_file_path": f".github/workflows/{workflow_path}",
        "default_profile": profile,
        "requested_profile": profile,
        "providers": {"coderabbit": "success", "codex": "success"},
        "final_candidate": {"admitted": True, "head_sha": HEAD_SHA},
        "changed_files": ["package.json", "package-lock.json"],
    }
    value.update(overrides)
    return value


def test_policy_rejects_mutable_source_and_profile_downgrade() -> None:
    """Catches target-controlled workflow provenance or profile input weakening the gate."""
    module = load_policy()
    mutable = pull_request_context(workflow_ref="koios-ai/ci-platform/.github/workflows/merge-gate-node-v1.yml@main")
    with pytest.raises(ValueError, match="workflow"):
        module.evaluate(mutable)
    with pytest.raises(ValueError, match="profile"):
        module.evaluate(pull_request_context(requested_profile="baseline"))


def test_policy_explicitly_rejects_fork_pull_requests() -> None:
    """Catches ambiguous base-origin checkout behavior being advertised as fork support."""
    module = load_policy()
    context = pull_request_context()
    context["event"]["pull_request"]["head"]["repo"] = {
        "id": 999,
        "full_name": "outside/fork",
    }
    with pytest.raises(ValueError, match="fork pull requests are explicitly unsupported"):
        module.evaluate(context)


def test_policy_blocks_draft_and_unobservable_ready_transition() -> None:
    """Catches draft or ready-for-review activity synthesizing final admission."""
    module = load_policy()
    draft = pull_request_context()
    draft["event"]["pull_request"]["draft"] = True
    assert module.evaluate(draft)["blocker"] == "draft-to-ready-hosted-rerun-canary"
    ready = pull_request_context()
    ready["event"]["action"] = "ready_for_review"
    assert module.evaluate(ready)["blocker"] == "draft-to-ready-hosted-rerun-canary"


def test_policy_rapid_multipush_cancels_by_pr_but_binds_each_head() -> None:
    """Catches concurrency that lets stale multipush finalization survive or loses exact-head binding."""
    module = load_policy()
    first = module.evaluate(pull_request_context())
    second_context = pull_request_context()
    second_context["event"]["pull_request"]["head"]["sha"] = "c" * 40
    second_context["final_candidate"]["head_sha"] = "c" * 40
    second = module.evaluate(second_context)
    assert first["concurrency_group"] == second["concurrency_group"] == "merge-gate-v1-node-123-pr-17"
    assert first["head_sha"] == HEAD_SHA
    assert second["head_sha"] == "c" * 40


def test_policy_concurrency_is_profile_scoped() -> None:
    """Catches overlapping profile ruleset runs cancelling a different source workflow."""
    module = load_policy()
    node = module.evaluate(pull_request_context(default_profile="node"))
    python = module.evaluate(pull_request_context(default_profile="python"))
    assert node["concurrency_group"] != python["concurrency_group"]


def test_policy_fails_closed_on_provider_timeout() -> None:
    """Catches an inconclusive hosted provider response being promoted to PASS."""
    module = load_policy()
    context = pull_request_context(providers={"coderabbit": "timeout", "codex": "success"})
    result = module.evaluate(context)
    assert result["admitted"] is False
    assert result["blocker"] == "provider-coderabbit-timeout"


@pytest.mark.parametrize("profile", ["node", "powershell"])
def test_native_profiles_skip_python_dependency_test_security_and_coverage_lanes(profile: str) -> None:
    """Catches native repositories being routed through pip, Bandit, pytest, or Python coverage."""
    module = load_policy()
    lanes = module.execution_lanes(profile)
    assert lanes["native"] is True
    assert lanes["python_dependencies"] is False
    assert lanes["python_tests"] is False
    assert lanes["bandit"] is False
    assert lanes["python_coverage"] is False
    assert lanes["coverage_status"] == "not-applicable"
    assert lanes["coverage_reason"]
    assert lanes["security_status"] == "required"
    expected_extension = "required" if profile == "node" else "not-applicable"
    assert lanes["security_extension_status"] == expected_extension
    if expected_extension == "not-applicable":
        assert lanes["security_reason"]


@pytest.mark.parametrize("profile", ["baseline", "python", "critical-ml"])
def test_non_native_profiles_have_reachable_policy_valid_lanes(profile: str) -> None:
    """Catches baseline/Python/ML profiles remaining deliberate workflow failures."""
    module = load_policy()
    lanes = module.execution_lanes(profile)
    assert lanes["native"] is False
    assert lanes["deterministic_status"] == "required"
    assert lanes["security_status"] == "required"
    if profile == "baseline":
        assert lanes["coverage_status"] == "not-applicable"
        assert lanes["security_extension_status"] == "not-applicable"
        assert lanes["security_reason"] and lanes["coverage_reason"]
    else:
        assert lanes["security_extension_status"] == "required"
        assert lanes["coverage_status"] == "required"


def test_policy_dependabot_is_closed_without_secrets_or_synthetic_pass() -> None:
    """Catches dependency updates bypassing exact-head finalization through unavailable credentials."""
    module = load_policy()
    context = pull_request_context()
    context["event"]["pull_request"]["user"] = {
        **DEPENDABOT_USER,
        "avatar_url": "https://avatars.githubusercontent.com/in/29110?v=4",
        "site_admin": False,
    }
    context["event"]["sender"]["login"] = "maintainer"
    result = module.evaluate(context)
    assert result["admitted"] is False
    assert result["blocker"] == "dependabot-no-secret-finalization"
    assert result["provider_results"] == {}
    assert result["dependabot_scope_digest"]


def test_policy_dependabot_identity_and_scope_are_bound_to_exact_head() -> None:
    """Catches sender-only detection or dependency PRs carrying arbitrary source changes."""
    module = load_policy()
    context = pull_request_context()
    context["event"]["pull_request"]["user"] = {**DEPENDABOT_USER, "html_url": "https://github.com/apps/dependabot"}
    context["event"]["sender"]["login"] = "maintainer"
    context["changed_files"] = ["src/backdoor.py", "package-lock.json"]
    result = module.evaluate(context)
    assert result["admitted"] is False
    assert result["blocker"] == "dependabot-identity-or-scope-unverified"

    wrong_repository = pull_request_context()
    wrong_repository["event"]["pull_request"]["user"] = {**DEPENDABOT_USER, "extra": "real-shaped"}
    wrong_repository["event"]["pull_request"]["head"]["repo"]["id"] = 456
    with pytest.raises(ValueError, match="fork pull requests are explicitly unsupported"):
        module.evaluate(wrong_repository)

    mismatched_identity = pull_request_context()
    mismatched_identity["event"]["pull_request"]["user"] = {**DEPENDABOT_USER, "id": 1, "extra": "real-shaped"}
    assert module.evaluate(mismatched_identity)["blocker"] != "dependabot-no-secret-finalization"

    forged = pull_request_context()
    forged["event"]["sender"]["login"] = "dependabot[bot]"
    forged["event"]["pull_request"]["user"] = {
        "login": "attacker",
        "id": 99,
        "node_id": "fake",
        "type": "User",
    }
    assert module.evaluate(forged)["blocker"] != "dependabot-no-secret-finalization"


def test_dependabot_changed_files_include_deletions_and_both_rename_paths(tmp_path: Path) -> None:
    """Catches deleted or renamed source paths disappearing from dependency-only scope."""
    module = load_policy()
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    (tmp_path / "src" / "deleted.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "src" / "renamed.py").write_text("VALUE = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "base"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}\n', encoding="utf-8")
    (tmp_path / "src" / "deleted.py").unlink()
    subprocess.run(
        ["git", "mv", "src/renamed.py", "requirements.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "add", "--all"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "head"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    context = pull_request_context()
    pull_request = context["event"]["pull_request"]
    pull_request["base"]["sha"] = base_sha
    pull_request["head"]["sha"] = head_sha
    changed_files = module._changed_files(tmp_path, "pull_request", context["event"])

    assert set(changed_files) == {
        "package-lock.json",
        "requirements.txt",
        "src/deleted.py",
        "src/renamed.py",
    }
    pull_request["user"] = DEPENDABOT_USER
    context["changed_files"] = changed_files
    assert module.evaluate(context)["blocker"] == "dependabot-identity-or-scope-unverified"


def test_dependabot_scope_includes_unchanged_source_of_a_copied_dependency_path(
    tmp_path: Path,
) -> None:
    """Catches copying unchanged source bytes onto an allowed manifest path to evade scope proof."""
    module = load_policy()
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "unchanged.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "base"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    (tmp_path / "requirements.txt").write_bytes((tmp_path / "src" / "unchanged.py").read_bytes())
    subprocess.run(["git", "add", "requirements.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "head"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    context = pull_request_context()
    pull_request = context["event"]["pull_request"]
    pull_request["base"]["sha"] = base_sha
    pull_request["head"]["sha"] = head_sha
    changed_files = module._changed_files(tmp_path, "pull_request", context["event"])

    assert changed_files == ["src/unchanged.py", "requirements.txt"]
    pull_request["user"] = DEPENDABOT_USER
    context["changed_files"] = changed_files
    assert module.evaluate(context)["blocker"] == "dependabot-identity-or-scope-unverified"


def test_policy_merge_group_binds_synthetic_sha_and_never_copies_ai_pass() -> None:
    """Catches PR-head provider success being relabeled onto a merge-group SHA."""
    module = load_policy()
    context = pull_request_context(
        event_name="merge_group",
        event={
            "merge_group": {"head_sha": "d" * 40, "base_sha": "e" * 40},
            "repository": {"id": 123},
            "sender": {"login": "github-merge-queue[bot]"},
        },
    )
    result = module.evaluate(context)
    assert result["head_sha"] == "d" * 40
    assert result["admitted"] is False
    assert result["blocker"] == "merge-group-ai-mapping-canary"
    assert result["provider_results"] == {}


@pytest.mark.parametrize("event_name", ["push", "schedule"])
def test_policy_rejects_main_and_schedule_events(event_name: str) -> None:
    """Catches non-required continuous validation impersonating PR merge admission."""
    module = load_policy()
    with pytest.raises(ValueError, match="event"):
        module.evaluate(pull_request_context(event_name=event_name))
