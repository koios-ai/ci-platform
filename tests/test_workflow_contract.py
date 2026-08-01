from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CONSUMER_WORKFLOWS = ROOT / "templates" / "consumer" / ".github" / "workflows"
CONTRACT_PATH = ROOT / "contract" / "v1.json"

PROFILES = ["baseline", "python", "node", "powershell", "critical-ml"]
INPUTS = {
    "profile",
    "head_sha",
    "base_sha",
    "changed_files_digest",
    "python_version",
    "artifact_retention_days",
}
OUTPUTS = {
    "head_sha",
    "profile",
    "deterministic_passed",
    "coverage_passed",
    "security_passed",
    "evidence_digest",
}
CONTEXTS = [
    "CI / required",
    "Security / required",
    "Coverage / required",
    "AI / CodeRabbit final",
    "AI / Codex final",
    "AI / findings resolved",
]
PLATFORM_CONTEXTS = set(CONTEXTS[:3])
AI_CONTEXTS = set(CONTEXTS[3:])
PUBLISHED_CONTEXTS = set(CONTEXTS) - {"CI / required"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
BASELINE_TEST_POLICY = {
    "version": 1,
    "test_roots": [],
    "marker_exclusions": [],
    "registered_markers": [],
    "disabled_plugins": [],
    "protected_support_files": [],
    "coverage_sources": [],
    "critical_tests": {
        "leakage": [],
        "lineage": [],
        "model": [],
        "parity": [],
        "schema": [],
    },
    "unexpected_skip_policy": "fail",
}


class ActionsLoader(yaml.SafeLoader):
    """YAML 1.2-like loader that does not coerce the key ``on`` to bool."""

    yaml_implicit_resolvers: ClassVar = {
        key: list(value) for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }


for first_char, resolvers in list(ActionsLoader.yaml_implicit_resolvers.items()):
    ActionsLoader.yaml_implicit_resolvers[first_char] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
ActionsLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def parse_actions_yaml(raw: str) -> Any:
    """Parse Actions YAML through the restricted SafeLoader subclass."""
    loader = ActionsLoader(raw)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_workflow(name: str) -> dict[str, Any]:
    path = WORKFLOWS / name
    assert path.is_file(), f"missing workflow: {path.relative_to(ROOT)}"
    loaded = parse_actions_yaml(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def load_contract() -> dict[str, Any]:
    assert CONTRACT_PATH.is_file(), "contract/v1.json must exist"
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def load_consumer_workflow(name: str) -> dict[str, Any]:
    path = CONSUMER_WORKFLOWS / name
    assert path.is_file(), f"missing consumer template: {path.relative_to(ROOT)}"
    loaded = parse_actions_yaml(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def iter_jobs() -> list[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    jobs: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = load_workflow(path.name)
        for job_id, job in workflow.get("jobs", {}).items():
            jobs.append((path.name, job_id, job, workflow))
    return jobs


def iter_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps", [])
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def effective_permissions(workflow: dict[str, Any], job: dict[str, Any]) -> dict[str, str]:
    permissions = job.get("permissions", workflow.get("permissions", {}))
    assert isinstance(permissions, dict)
    return {str(key): str(value) for key, value in permissions.items()}


def test_contract_schema_is_closed_and_exact() -> None:
    """Catches added profiles, command inputs, loose SHAs, and excess retention."""
    contract = load_contract()

    assert contract["additionalProperties"] is False
    assert set(contract["required"]) == INPUTS
    assert set(contract["properties"]) == INPUTS
    assert contract["properties"]["profile"]["enum"] == PROFILES
    assert contract["properties"]["head_sha"]["pattern"] == "^[0-9a-f]{40}$"
    assert contract["properties"]["base_sha"]["pattern"] == "^[0-9a-f]{40}$"
    assert contract["properties"]["changed_files_digest"]["pattern"] == "^[0-9a-f]{64}$"
    assert contract["properties"]["python_version"]["default"] == "3.12"
    assert contract["properties"]["artifact_retention_days"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 7,
        "default": 3,
    }
    assert set(contract["x-outputs"]) == OUTPUTS
    assert contract["x-required-contexts"] == CONTEXTS
    assert contract["x-consumer-test-policy"] == {
        "path": ".github/ci-platform-test-policy.json",
        "schema": "contract/test-policy-v1.schema.json",
        "source": "exact-protected-base-commit",
        "commands_permitted": False,
        "unexpected_skip_policy": "fail",
        "critical_categories": [
            "leakage",
            "lineage",
            "model",
            "parity",
            "schema",
        ],
        "coverage_floor_source": "quality_debt.yml",
    }
    assert contract["x-fast-test-lane"] == {
        "policy_source": "exact-protected-base-commit",
        "selection": [
            "changed-declared-tests",
            "direct-static-import-consumers",
            "basename-matches",
            "explicit-critical-manifest",
        ],
        "maximum_selected_tests": 128,
        "dependency_setup": "protected-base-established-fixed-strategy",
        "full_tree_fallback": False,
        "unexpected_skip_policy": "fail",
        "job_timeout_minutes": 20,
    }


def test_contract_assigns_platform_and_ai_contexts_to_distinct_publishers() -> None:
    """Catches a PR-code workflow taking ownership of a published result."""
    owners = load_contract()["x-context-owners"]

    assert set(owners) == set(CONTEXTS)
    assert owners["CI / required"]["publisher"] == "organization-required-workflow-terminal"
    assert {name for name, owner in owners.items() if owner["publisher"] == "checks-api"} == PUBLISHED_CONTEXTS
    assert owners["Security / required"]["publisher"] == "checks-api"
    assert owners["Coverage / required"]["publisher"] == "checks-api"
    for context in set(CONTEXTS) - {"CI / required"}:
        assert owners[context]["target"] == "pull-request-head"
        assert owners[context]["trusted_metadata_only"] is True


def test_consumer_tree_has_exactly_five_distinct_check_publishers() -> None:
    """Catches a bundled context writer or a sixth checks-write escape hatch."""
    expected = {
        ("final-required.yml", "publish-security"),
        ("final-required.yml", "publish-coverage"),
        ("coderabbit-final.yml", "publish-coderabbit"),
        ("codex-final-gate.yml", "publish-codex"),
        ("ai-findings-resolved.yml", "publish-findings"),
    }
    publishers: set[tuple[str, str]] = set()
    for path in sorted(CONSUMER_WORKFLOWS.glob("*.yml")):
        workflow = load_consumer_workflow(path.name)
        assert workflow["permissions"] == {}
        for job_id, job in workflow["jobs"].items():
            permissions = effective_permissions(workflow, job)
            assert permissions.get("statuses") != "write", (path.name, job_id)
            if permissions.get("checks") == "write":
                publishers.add((path.name, str(job_id)))
                expected_permissions = {
                    "actions": "read",
                    "checks": "write",
                    "contents": "read",
                    "pull-requests": "read",
                }
                if (path.name, str(job_id)) == (
                    "final-required.yml",
                    "publish-security",
                ):
                    expected_permissions["statuses"] = "read"
                assert permissions == expected_permissions
                serialized = json.dumps(job)
                assert "pull_request.head.sha" not in " ".join(
                    str(step.get("with", {}).get("ref", "")) for step in iter_steps(job)
                )
                assert '"run":' not in serialized
    assert publishers == expected

    owners = load_contract()["x-context-owners"]
    assert {owner["controller"] for name, owner in owners.items() if name != "CI / required"} == {
        f".github/workflows/{workflow}:{job}" for workflow, job in expected
    }


def test_consumer_oidc_is_only_the_no_checkout_coverage_uploader() -> None:
    oidc_jobs: list[tuple[str, str, dict[str, Any]]] = []
    for path in sorted(CONSUMER_WORKFLOWS.glob("*.yml")):
        workflow = load_consumer_workflow(path.name)
        for job_id, job in workflow["jobs"].items():
            if effective_permissions(workflow, job).get("id-token") == "write":
                oidc_jobs.append((path.name, str(job_id), job))
    assert [(name, job_id) for name, job_id, _ in oidc_jobs] == [("final-required.yml", "coverage-upload")]
    job = oidc_jobs[0][2]
    assert all(
        not str(step.get("uses", "")).startswith("actions/checkout@") and "run" not in step for step in iter_steps(job)
    )
    assert "secrets." not in json.dumps(job)


def test_ai_publishers_use_consumer_local_evidence_without_provider_synthesis() -> None:
    """Catches a central action inventing a CodeRabbit or Codex pass."""
    script = ROOT / "templates" / "consumer" / ".github" / "ci" / "evaluate_ai_provider.py"
    assert script.is_file()
    raw_script = script.read_text(encoding="utf-8")
    assert "coderabbitai[bot]" in raw_script
    assert "chatgpt-codex-connector[bot]" in raw_script
    assert "347564" in raw_script
    assert "1144995" in raw_script
    assert "review skipped" in raw_script
    assert "reviewThreads" in raw_script

    expected = {
        "coderabbit-final.yml": (
            "evaluate-coderabbit",
            "publish-coderabbit",
            "coderabbit",
            "coderabbit-final",
        ),
        "codex-final-gate.yml": (
            "evaluate-codex",
            "publish-codex",
            "codex",
            "codex-final",
        ),
        "ai-findings-resolved.yml": (
            "evaluate-findings",
            "publish-findings",
            "findings",
            "ai-findings",
        ),
    }
    for name, (evaluator_id, publisher_id, provider, concurrency_prefix) in expected.items():
        workflow = load_consumer_workflow(name)
        evaluator = workflow["jobs"][evaluator_id]
        publisher = workflow["jobs"][publisher_id]
        checkout = next(
            step for step in iter_steps(evaluator) if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        assert checkout["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
        assert checkout["with"]["persist-credentials"] is False
        command = next(str(step["run"]) for step in iter_steps(evaluator) if "run" in step)
        assert f"--provider {provider}" in command
        assert "--timeout-seconds 900" in command
        assert "--poll-seconds 30" in command
        assert "pull_request.head" not in command
        assert "ai-review-ready" in str(evaluator["if"])
        assert "ci-final" not in str(evaluator["if"])
        assert "dependabot[bot]" in str(evaluator["if"])
        assert "ai-review-ready" in str(publisher["if"])
        assert "ci-final" not in str(publisher["if"])
        assert "dependabot[bot]" in str(publisher["if"])
        assert workflow["concurrency"] == {
            "group": (
                concurrency_prefix + "-${{ github.repository_id }}-${{ github.event.pull_request.number }}-${{ "
                "github.event.label.name == 'ai-review-ready' && 'candidate' || github.run_id }}"
            ),
            "cancel-in-progress": True,
        }
        publish_action = iter_steps(publisher)[-1]
        assert publish_action["uses"].startswith("koios-ai/ci-platform/.github/actions/publish-ai-context@")
        assert publish_action["with"]["evaluation_result"].startswith("${{ needs.")


def test_coderabbit_configuration_is_closed_label_only_and_nonwriting() -> None:
    path = ROOT / "templates" / "consumer" / ".coderabbit.yaml"
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert config == {
        "language": "en-US",
        "early_access": False,
        "inheritance": False,
        "reviews": {
            "profile": "assertive",
            "request_changes_workflow": True,
            "review_status": True,
            "review_progress": True,
            "fail_commit_status": True,
            "auto_review": {
                "enabled": False,
                "description_keyword": "",
                "auto_incremental_review": False,
                "auto_pause_after_reviewed_commits": 1,
                "ignore_title_keywords": [],
                "labels": ["ai-review-ready"],
                "drafts": False,
                "base_branches": [],
                "ignore_usernames": [
                    "dependabot[bot]",
                    "renovate[bot]",
                    "github-actions[bot]",
                    "coderabbitai[bot]",
                    "chatgpt-codex-connector[bot]",
                ],
            },
            "finishing_touches": {
                "docstrings": {"enabled": False},
                "unit_tests": {"enabled": False},
                "simplify": {"enabled": False},
                "autofix": {"enabled": False},
                "fix_ci": {"enabled": False},
                "resolve_merge_conflict": {"enabled": False},
                "custom": [],
            },
        },
    }


def test_legacy_required_workflow_is_not_a_v1_ruleset_candidate() -> None:
    """Catches the superseded required.yml remaining selectable beside merge-gate-v1."""
    workflow = load_workflow("required.yml")

    assert workflow["name"] == "LEGACY / inactive required integrity"
    assert workflow["on"] == {"workflow_dispatch": None}
    assert workflow["jobs"]["required"]["name"] != "CI / required"
    assert workflow["concurrency"] == {
        "group": (
            "required-${{ github.repository_id }}-${{ "
            "github.event.pull_request.number || github.event.merge_group.head_sha }}"
        ),
        "cancel-in-progress": True,
    }
    assert workflow["permissions"] == {"contents": "read"}


def test_label_invalidation_is_explicitly_not_same_sha_context_invalidation() -> None:
    workflow = load_consumer_workflow("invalidate-final-labels.yml")
    assert workflow["on"]["pull_request_target"]["branches"] == ["main"]
    assert workflow["on"]["pull_request_target"]["types"] == [
        "synchronize",
        "reopened",
        "converted_to_draft",
    ]
    assert "ready_for_review" not in workflow["on"]["pull_request_target"]["types"]
    contract = load_contract()["x-sha-invalidation-controller"]
    assert contract["implementation_status"] == "implemented-hosted-unverified"
    assert contract["design_template"] == "templates/consumer/.github/workflows/invalidate-final-labels.yml"
    assert contract["planned_consumer_path"] == ".github/workflows/invalidate-final-labels.yml"
    assert contract["platform_canary_workflow"] == ".github/workflows/invalidate-final-labels.yml"
    assert contract["hosted_readback_required"] is True
    assert "workflow" not in contract
    assert "job" not in contract
    assert contract["labels_only"] is True
    assert contract["required_check_contexts_invalidated"] is False
    assert contract["same_sha_lifecycle_transitions_blocked_until_external_enforcement"] == [
        "closed-to-reopened",
        "draft-to-ready",
    ]


def test_platform_installs_a_trusted_lifecycle_invalidator_canary() -> None:
    workflow = load_workflow("invalidate-final-labels.yml")
    assert workflow["on"] == {
        "pull_request_target": {
            "branches": ["main"],
            "types": ["synchronize", "reopened", "converted_to_draft"],
        }
    }
    assert workflow["permissions"] == {}
    assert workflow["concurrency"]["cancel-in-progress"] is True
    job = workflow["jobs"]["invalidate-final-labels"]
    assert job["if"] == "github.event.pull_request.head.repo.full_name == github.repository"
    assert job["permissions"] == {"contents": "read", "issues": "write", "pull-requests": "read"}
    checkout, action = iter_steps(job)
    assert checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert checkout["with"] == {
        "ref": "${{ github.event.pull_request.base.sha }}",
        "persist-credentials": False,
        "sparse-checkout": ".github/actions/invalidate-final-labels",
    }
    assert action["uses"] == "./.github/actions/invalidate-final-labels"
    assert action["with"]["event_head_sha"] == "${{ github.event.pull_request.head.sha }}"
    assert action["with"]["lifecycle_event"] == "${{ github.event.action }}"


def test_exact_head_finalizer_uses_github_native_non_cancelling_singleflight() -> None:
    workflow = load_consumer_workflow("finalize-python-v1.yml")
    assert workflow["on"] == {"workflow_dispatch": {"inputs": workflow["on"]["workflow_dispatch"]["inputs"]}}
    assert workflow["run-name"].startswith("koios-finalizer-v1|repo=${{ github.repository_id }}")
    assert workflow["concurrency"] == {
        "group": (
            "koios-finalizer-v1-${{ github.repository_id }}-${{ inputs.pull_request_number }}-${{ inputs.head_sha }}"
        ),
        "cancel-in-progress": False,
    }
    job = workflow["jobs"]["finalize"]
    assert job["if"] == ("github.actor == 'github-actions[bot]' && github.triggering_actor == 'github-actions[bot]'")
    assert job["permissions"] == {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    }
    assert job["env"]["KOIOS_EXTERNAL_SINGLEFLIGHT_VERIFIED"] == ("${{ vars.KOIOS_EXTERNAL_SINGLEFLIGHT_VERIFIED }}")
    command = next(str(step["run"]) for step in iter_steps(job) if "run" in step)
    assert "--rerun-failed" not in command
    assert "scripts/koios_ci.py finalize" in command


def test_exact_attempt_subject_exposes_every_supported_profile_and_finishes_before_handoff() -> None:
    workflow = load_consumer_workflow("final-subject-v1.yml")
    assert workflow["run-name"].startswith("koios-final-subject-v1|repo=${{ github.repository_id }}")
    assert workflow["on"].keys() == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["profile"]["options"] == PROFILES
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert set(workflow["jobs"]) == {"platform-final"}
    platform = workflow["jobs"]["platform-final"]
    assert platform["if"] == (
        "github.actor == 'github-actions[bot]' && github.triggering_actor == 'github-actions[bot]'"
    )
    assert platform["uses"] == ("koios-ai/ci-platform/.github/workflows/reusable-final.yml@__CI_PLATFORM_FULL_SHA__")
    assert "rerun" not in str(workflow).lower()


def test_exact_attempt_resume_is_automatic_only_after_the_subject_completed() -> None:
    workflow = load_consumer_workflow("resume-finalizer-v1.yml")
    assert workflow["on"] == {
        "workflow_run": {
            "workflows": ["Exact-head final subject"],
            "branches": ["main"],
            "types": ["completed"],
        }
    }
    assert workflow["concurrency"]["cancel-in-progress"] is False
    job = workflow["jobs"]["dispatch-finalizer"]
    assert job["if"] == (
        "github.run_attempt == 1 && "
        "github.actor == 'github-actions[bot]' && "
        "github.triggering_actor == 'github-actions[bot]' && "
        "github.event.workflow_run.conclusion == 'success' && "
        "github.event.workflow_run.event == 'workflow_dispatch' && "
        "github.event.workflow_run.head_branch == 'main'"
    )
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    action = iter_steps(job)[-1]
    assert action["uses"] == ("koios-ai/ci-platform/.github/actions/dispatch-finalizer@__CI_PLATFORM_FULL_SHA__")
    assert action["with"]["subject_run_id"] == "${{ github.event.workflow_run.id }}"
    assert action["with"]["subject_run_attempt"] == "${{ github.event.workflow_run.run_attempt }}"
    assert action["with"]["subject_workflow_id"] == "${{ github.event.workflow_run.workflow_id }}"
    assert "rerun" not in str(workflow).lower()


def test_every_privileged_pr_target_controller_is_scoped_to_main() -> None:
    assert load_contract()["x-protected-default-branch"] == "main"
    expected_types = {
        "final-required.yml": ["labeled"],
        "coderabbit-final.yml": ["labeled"],
        "codex-final-gate.yml": ["labeled"],
        "ai-findings-resolved.yml": ["labeled"],
        "invalidate-final-labels.yml": [
            "synchronize",
            "reopened",
            "converted_to_draft",
        ],
    }
    for name, types in expected_types.items():
        trigger = load_consumer_workflow(name)["on"]["pull_request_target"]
        assert trigger["branches"] == ["main"], name
        assert trigger["types"] == types, name


def test_initial_rollout_fails_closed_without_merge_queue() -> None:
    """Catches enabling a queue before all six contexts bind its synthetic SHA."""
    guard = load_contract()["x-rollout-guards"]["merge_queue"]
    assert guard == {
        "initially_enabled": False,
        "required_context_count": len(CONTEXTS),
        "synthetic_sha_binding_required": True,
        "pr_head_success_relabeling_permitted": False,
        "activation_gate": "hosted-fail-closed-mapping-canary",
    }
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Do **not** enable a merge-queue rule during the initial rollout" in readme
    assert "PR-head AI success must never be copied or relabeled" in readme
    assert load_contract()["x-rollout-guards"]["branch_freshness"] == {
        "strict_up_to_date_required": True,
        "reason": "Context-only rules cannot see the base SHA bound inside old PR-head evidence.",
        "until": "all-required-contexts-bind-merge-group-sha",
    }
    assert "strict “branch must be up to date”" in readme


def test_cutover_remains_blocked_for_unresolved_architectural_requirements() -> None:
    status = load_contract()["x-rollout-status"]
    assert status["cutover_permitted"] is False
    assert status["disposition"] == "NOT READY"
    assert {item["id"] for item in status["blocking_requirements"]} == {
        "same-head-latest-attempt-enforcement",
        "untrusted-execution-isolation",
        "dependabot-admission",
        "protected-main-and-scheduled-validation",
        "same-repository-branch-actions-boundary",
        "provider-native-evidence-canaries",
        "supported-release-manifest",
        "github-token-ai-cadence-dispatch",
    }
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "NOT READY — CUTOVER IS FORBIDDEN" in readme
    assert "older successful manual contexts" in readme
    assert "before any job starts" in readme


def test_reusable_final_interface_matches_contract() -> None:
    """Catches caller drift and accidental command or secret parameters."""
    workflow = load_workflow("reusable-final.yml")
    call = workflow["on"]["workflow_call"]

    assert set(workflow["on"]) == {"workflow_call"}
    assert set(call["inputs"]) == INPUTS
    assert set(call["outputs"]) == OUTPUTS
    assert call["inputs"]["python_version"]["default"] == "3.12"
    assert call["inputs"]["artifact_retention_days"]["default"] == 3
    assert call.get("secrets") in (None, {})
    for name in OUTPUTS:
        assert call["outputs"][name]["value"].startswith("${{ jobs.")


def test_security_is_folded_into_the_final_output_contract() -> None:
    """Catches a detached security run with no final evidence dependency."""
    workflow = load_workflow("reusable-final.yml")
    security = next(job for job in workflow["jobs"].values() if job.get("name") == "Platform / security evidence")
    deterministic = workflow["jobs"]["deterministic"]
    assert "security" in deterministic["needs"]
    assert security["outputs"]["evidence_digest"]
    assert workflow["on"]["workflow_call"]["outputs"]["security_passed"]["value"] == (
        "${{ jobs.security.outputs.passed }}"
    )
    owner = load_contract()["x-context-owners"]["Security / required"]
    assert owner["native_provider_evidence"] == {
        "provider": "DeepSource",
        "activation": "trusted-base-.deepsource.toml",
        "target": "exact-pull-request-head",
        "required_configured_dependency_contexts": True,
        "retained_signal_policy": "defense-in-depth-until-central-parity-proven",
        "retained_sca_signals": [
            "reachability",
            "dynamic-risk",
            "epss",
            "cvss",
            "license-compliance",
        ],
        "ai_review_desired_state": "disabled",
        "ai_review_disabled_readback_required": True,
        "ai_review_context_permitted": False,
        "observed_ai_review_context_policy": "fail-closed-hosted-drift",
        "ignore_disabled_test_coverage": True,
        "fail_on_no_data_required": True,
        "checked_in_configuration_required": True,
        "local_wrapper_removal_gate": "hosted-exact-head-canary",
    }
    publisher = load_consumer_workflow("final-required.yml")["jobs"]["publish-security"]
    assert publisher["env"]["CI_PLATFORM_ROLE"] == "security-context-publisher"
    assert (
        effective_permissions(
            load_consumer_workflow("final-required.yml"),
            publisher,
        )["statuses"]
        == "read"
    )


def test_final_success_promoter_is_exact_head_fail_closed_and_not_a_check_writer() -> None:
    """Catches AI review starting before both owned final contexts succeed."""
    workflow = load_consumer_workflow("final-required.yml")
    promoter = workflow["jobs"]["promote-ai-review"]
    permissions = effective_permissions(workflow, promoter)

    assert workflow["concurrency"] == {
        "group": (
            "final-${{ github.repository_id }}-"
            "${{ github.event.pull_request.number }}-"
            "${{ github.event.label.name == 'ci-final' && "
            "'candidate' || github.run_id }}"
        ),
        "cancel-in-progress": True,
    }
    assert promoter["needs"] == [
        "final-preflight",
        "publish-security",
        "publish-coverage",
    ]
    assert permissions == {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    }
    assert promoter["env"]["CI_PLATFORM_ROLE"] == "ai-review-promoter"
    condition = str(promoter["if"])
    for required in (
        "needs.final-preflight.outputs.ready == 'true'",
        "needs.publish-security.outputs.published == 'true'",
        "needs.publish-security.outputs.conclusion == 'success'",
        "needs.publish-coverage.outputs.published == 'true'",
        "needs.publish-coverage.outputs.conclusion == 'success'",
    ):
        assert required in condition
    step = iter_steps(promoter)[0]
    assert step["uses"].startswith("koios-ai/ci-platform/.github/actions/promote-ai-review@")
    assert step["with"]["expected_head_sha"] == ("${{ needs.final-preflight.outputs.head_sha }}")
    assert "checks" not in {key for key, value in permissions.items() if value == "write"}

    for job_name in ("publish-security", "publish-coverage"):
        publisher = workflow["jobs"][job_name]
        assert publisher["outputs"] == {
            "published": "${{ steps.publish.outputs.published }}",
            "conclusion": "${{ steps.publish.outputs.conclusion }}",
        }
        assert iter_steps(publisher)[0]["id"] == "publish"

    cadence = load_contract()["x-ai-review-cadence"]
    assert cadence == {
        "final_success_promoter": (".github/workflows/final-required.yml:promote-ai-review"),
        "source_label": "ci-final",
        "review_label": "ai-review-ready",
        "promotion_requires": ["Security / required", "Coverage / required"],
        "provider_controllers": [
            ".github/workflows/coderabbit-final.yml",
            ".github/workflows/codex-final-gate.yml",
            ".github/workflows/ai-findings-resolved.yml",
        ],
        "promotion_target": "exact-pull-request-head",
        "provider_native_evidence": {
            "coderabbit": "exact-head-review-plus-App-delivery-plus-App-check",
            "codex": "exact-head-review-plus-App-delivery-hosted-canary-disabled-by-default",
            "provider_and_head_bound": True,
            "complete_review_thread_readback": True,
            "unresolved_threads": 0,
            "failure_markers": 0,
            "synthetic_pass_envelope_permitted": False,
            "hosted_canary_required": True,
        },
        "superseded_attempts_rejected": True,
        "candidate_concurrency_group": "ci-final-only",
        "noncandidate_label_runs_isolated": True,
        "github_token_label_event_triggers_workflows": False,
        "current_provider_controller_dispatch": "nonfunctional",
        "label_is_orchestration_authority": False,
        "current_label_trigger_provenance": "untrusted",
        "required_resolution": [
            "same-trusted-final-workflow-downstream-jobs",
            "exact-head-revalidated-workflow-dispatch-or-repository-dispatch",
        ],
    }
    topology = load_contract()["x-consumer-final-topology"]["jobs"]["promote-ai-review"]
    assert topology["role"] == "ai-review-promoter"
    assert topology["needs"] == promoter["needs"]
    assert topology["permissions"] == permissions


def test_only_immutable_fast_context_is_a_workflow_job_name() -> None:
    """Catches source-repository jobs or reusable prefixes impersonating contexts."""
    counts = Counter(str(job.get("name")) for _, _, job, _ in iter_jobs() if job.get("name") in set(CONTEXTS))

    assert all(counts[context] == 0 for context in CONTEXTS)

    profile_workflows = load_contract()["x-merge-gate-v1"]["profile_workflows"]
    assert set(profile_workflows) == set(PROFILES)
    for profile, relative_path in profile_workflows.items():
        workflow = load_workflow(Path(relative_path).name)
        terminal = workflow["jobs"]["merge"]
        assert terminal["name"] == (
            "${{ github.repository == 'koios-ai/ci-platform' "
            f"&& 'Koios CI / {profile} consumer gate disabled' || 'CI / required' }}}}"
        )
        assert terminal["if"] == "github.repository != 'koios-ai/ci-platform' && always()"


def test_pr_head_execution_is_read_only_secret_free_and_without_oidc() -> None:
    """Catches privilege escalation in any job that checks out target code."""
    saw_checkout = False
    for workflow_name, job_id, job, workflow in iter_jobs():
        steps = iter_steps(job)
        checkout_steps = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
        if not checkout_steps:
            continue
        saw_checkout = True
        permissions = effective_permissions(workflow, job)
        if (workflow_name, job_id) == ("invalidate-final-labels.yml", "invalidate-final-labels"):
            assert checkout_steps[0]["with"] == {
                "ref": "${{ github.event.pull_request.base.sha }}",
                "persist-credentials": False,
                "sparse-checkout": ".github/actions/invalidate-final-labels",
            }
            assert permissions == {"contents": "read", "issues": "write", "pull-requests": "read"}
            continue
        assert permissions == {"contents": "read"}, (workflow_name, job_id, permissions)
        assert "id-token" not in permissions
        serialized = json.dumps(job)
        assert "secrets." not in serialized
        assert "CODECOV_TOKEN" not in serialized
        for step in checkout_steps:
            assert step["with"]["persist-credentials"] is False
            assert step["with"]["ref"]
    assert saw_checkout


def test_oidc_is_isolated_to_no_checkout_coverage_upload() -> None:
    """Catches impossible OIDC elevation inside the read-only reusable core."""
    oidc_jobs: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    for item in iter_jobs():
        _, _, job, workflow = item
        if effective_permissions(workflow, job).get("id-token") == "write":
            oidc_jobs.append(item)

    assert oidc_jobs == []


def test_every_external_action_is_pinned_to_a_full_commit_sha() -> None:
    """Catches mutable tags and branches in the executable supply chain."""
    seen: list[str] = []
    for _, _, job, _ in iter_jobs():
        if "uses" in job:
            seen.append(str(job["uses"]))
        seen.extend(str(step["uses"]) for step in iter_steps(job) if "uses" in step)

    assert seen
    for reference in seen:
        if reference.startswith("./"):
            continue
        assert "@" in reference, reference
        pin = reference.rsplit("@", 1)[1]
        assert FULL_SHA.fullmatch(pin), reference


def test_reviewed_third_party_action_pins_are_exact() -> None:
    """Catches an unreviewed or mistyped SHA that is still syntactically full."""
    expected = {
        "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "codecov/codecov-action": "fb8b3582c8e4def4969c97caa2f19720cb33a72f",
    }
    observed: dict[str, set[str]] = {}
    roots = (ROOT / ".github", ROOT / "templates")
    for root in roots:
        for path in sorted(root.rglob("*.yml")):
            raw = path.read_text(encoding="utf-8")
            for locator, pin in re.findall(r"\buses:\s*([^\s@]+)@([^\s]+)", raw):
                if locator.startswith("koios-ai/ci-platform/"):
                    continue
                observed.setdefault(locator, set()).add(pin)

    assert observed == {locator: {pin} for locator, pin in expected.items()}


def test_no_secret_inheritance_or_input_interpolation_in_shell() -> None:
    """Catches an arbitrary shell input or broad secret forwarding primitive."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        raw = path.read_text(encoding="utf-8")
        assert "secrets: inherit" not in raw
        assert "CODECOV_TOKEN" not in raw
        assert "CODERABBIT_AUTOFIX_TOKEN" not in raw

        workflow = load_workflow(path.name)
        for _, job in workflow.get("jobs", {}).items():
            for step in iter_steps(job):
                run = str(step.get("run", ""))
                assert "${{ inputs." not in run, (path.name, step.get("name"))


def test_retention_is_bounded_and_manifest_is_verified_before_upload() -> None:
    """Catches long-lived evidence and uploading unverified coverage bytes."""
    contract = load_contract()
    assert contract["properties"]["artifact_retention_days"]["maximum"] == 7

    workflow = load_workflow("reusable-final.yml")
    upload_steps = [
        step
        for _, job in workflow["jobs"].items()
        for step in iter_steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(upload_steps) == 2
    assert all(step["with"]["retention-days"] == "${{ inputs.artifact_retention_days }}" for step in upload_steps)

    coverage_job = workflow["jobs"]["coverage-evidence"]
    step_names = [step.get("name") for step in iter_steps(coverage_job)]
    assert step_names.index("Verify evidence manifest") < step_names.index("Record coverage evidence success")


def test_required_fast_lane_has_substantive_generic_gates() -> None:
    """Catches a compile-only fast lane that can look green without CI."""
    workflow = load_workflow("required.yml")
    steps = workflow["jobs"]["required"]["steps"]
    names = {str(step.get("name")) for step in steps}
    assert {
        "Classify changed scope",
        "Select protected-base affected tests",
        "Scan changed files for high-confidence secrets",
        "Lint changed Python",
        "Check changed Python formatting",
        "Type-check changed Python",
        "Compile changed Python without imports",
        "Synchronize bounded fast-test environment",
        "Run protected-base affected tests",
        "Validate changed service and documentation files",
    } <= names
    serialized = json.dumps(workflow)
    raw = (WORKFLOWS / "required.yml").read_text(encoding="utf-8")
    assert "actions/cache" not in serialized
    assert "cache:" not in raw
    assert "platform/scripts/fast_test_selection.py" in raw
    assert "platform/scripts/run_fast_tests.py" in raw
    assert 'git cat-file -e "${BASE_SHA}:tools/sync_ci_environment.py"' in raw
    assert "tools/sync_ci_environment.py --ci" in raw
    assert "python -m pip check" in raw
    assert "compileall" not in raw
    assert '"tests", "test"' not in raw
    assert "changed path is a symbolic link" in raw


def test_required_validator_uses_separate_exact_target_and_platform_trees() -> None:
    """Catches path confusion or executing a PR-controlled validator."""
    workflow = load_workflow("required.yml")
    steps = iter_steps(workflow["jobs"]["required"])
    checkouts = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 2
    target, platform = checkouts
    assert target["with"] == {
        "fetch-depth": 0,
        "path": "target",
        "persist-credentials": False,
        "ref": "${{ env.HEAD_SHA }}",
    }
    assert platform["with"] == {
        "repository": "${{ job.workflow_repository }}",
        "ref": "${{ job.workflow_sha }}",
        "path": "platform",
        "persist-credentials": False,
    }
    validator = next(step for step in steps if step.get("name") == "Validate event and workflow integrity")
    command = str(validator["run"])
    assert "python platform/scripts/validate_consumer.py" in command
    assert "--root target" in command
    assert "target/scripts/validate_consumer.py" not in command
    assert validator["env"] == {
        "PLATFORM_REPOSITORY": "${{ job.workflow_repository }}",
        "PLATFORM_SHA": "${{ job.workflow_sha }}",
        "PLATFORM_REF": "${{ job.workflow_ref }}",
        "PLATFORM_FILE_PATH": "${{ job.workflow_file_path }}",
    }


def test_final_evidence_is_substantive_and_profile_aware() -> None:
    """Catches artifacts that attest only to their own existence."""
    workflow = load_workflow("reusable-final.yml")
    serialized = json.dumps(workflow)
    coverage_implementation = (ROOT / "scripts" / "evaluate_coverage.py").read_text(encoding="utf-8")
    step_names = {str(step.get("name")) for job in workflow["jobs"].values() for step in iter_steps(job)}
    assert {
        "Synchronize repository environment",
        "Verify installed dependency environment",
        "Run full typing and documentation gates",
        "Run import and CLI smoke gates",
        "Run protected-base test policy with coverage",
        "Enforce coverage floors",
        "Run repository-native pre-test policy hooks",
        "Run repository-native post-coverage policy hooks",
        "Enforce protected-base CI policy non-regression",
        "Run Bandit medium/high security gate",
    } <= step_names
    for field in (
        "quality_debt_digest",
        "changed_files_evidence_digest",
        "platform_sha",
        "coverage_summary_digest",
        "typing_summary_digest",
        "documentation_summary_digest",
        "environment_summary_digest",
        "critical_safety_summary_digest",
        "test_policy_summary_digest",
        "repository_pre_hooks_digest",
        "repository_post_hooks_digest",
        "policy_non_regression_digest",
    ):
        assert field in serialized
    assert "job.workflow_sha" in serialized
    assert "pip check" in serialized
    assert "tools/sync_ci_environment.py --ci" in serialized
    assert "bandit==1.9.4" in serialized
    assert "../platform/scripts/run_test_policy.py" in serialized
    assert "ci-platform-critical-tests.txt" not in serialized
    assert "global_coverage_floor" in coverage_implementation
    assert "diff_coverage_floor" in coverage_implementation
    assert "critical_patch_coverage_floor" in coverage_implementation


def test_codecov_oidc_upload_is_limited_to_the_verified_coverage_file() -> None:
    workflow = parse_actions_yaml(
        (ROOT / "templates" / "consumer" / ".github" / "workflows" / "final-required.yml").read_text(encoding="utf-8")
    )
    assert isinstance(workflow, dict)
    upload = next(
        step
        for step in workflow["jobs"]["coverage-upload"]["steps"]
        if str(step.get("uses", "")).startswith("codecov/codecov-action@")
    )
    assert upload["with"] == {
        "disable_search": True,
        "fail_ci_if_error": True,
        "files": "coverage.xml",
        "use_oidc": True,
    }


def test_merge_group_and_pr_head_sha_are_explicit() -> None:
    """Catches silently evaluating a stale merge or pull-request head."""
    workflow = load_workflow("required.yml")
    serialized = json.dumps(workflow)

    assert "github.event.pull_request.head.sha" in serialized
    assert "github.event.merge_group.head_sha" in serialized
    assert "github.event.pull_request.base.sha" in serialized
    assert "github.event.merge_group.base_sha" in serialized


def test_setup_python_action_has_no_command_escape_hatch() -> None:
    """Catches a consumer-controlled shell command in the setup boundary."""
    path = ROOT / ".github" / "actions" / "setup-python" / "action.yml"
    assert path.is_file()
    action = parse_actions_yaml(path.read_text(encoding="utf-8"))

    assert set(action["inputs"]) == {"python-version"}
    assert action["inputs"]["python-version"]["default"] == "3.12"
    for step in action["runs"]["steps"]:
        if "uses" in step:
            pin = str(step["uses"]).rsplit("@", 1)[1]
            assert FULL_SHA.fullmatch(pin)
        assert "${{ inputs." not in str(step.get("run", ""))


@cache
def _load_required_validator() -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    path = ROOT / "scripts" / "validate_consumer.py"
    spec = importlib.util.spec_from_file_location("ci_platform_validate_consumer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@cache
def _platform_head_sha() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()


def _run_required_validator(
    workflow_text: str,
    extra_files: dict[str, str] | None = None,
    *,
    workflow_name: str = "candidate.yml",
    platform_ref: str = "refs/heads/main",
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    process_boundary: bool = False,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / ".github" / "workflows" / workflow_name
        path.parent.mkdir(parents=True)
        path.write_text(workflow_text, encoding="utf-8")
        for relative, content in (extra_files or {}).items():
            extra = root / relative
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_text(content, encoding="utf-8")
        environment = os.environ.copy()
        environment.update({"HEAD_SHA": head_sha, "BASE_SHA": base_sha})
        platform_sha = _platform_head_sha()
        workflow_ref = "koios-ai/ci-platform/.github/workflows/required.yml@" + platform_ref
        command = [
            sys.executable,
            str(ROOT / "scripts" / "validate_consumer.py"),
            "--root",
            str(root),
            "--head-sha",
            head_sha,
            "--base-sha",
            base_sha,
            "--platform-repository",
            "koios-ai/ci-platform",
            "--platform-sha",
            platform_sha,
            "--platform-ref",
            workflow_ref,
            "--platform-file-path",
            ".github/workflows/required.yml",
        ]
        if process_boundary:
            return subprocess.run(
                command,
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        validator = _load_required_validator()
        try:
            validator.validate_platform_identity(
                platform_root=ROOT,
                repository="koios-ai/ci-platform",
                sha=platform_sha,
                workflow_ref=workflow_ref,
                workflow_file_path=".github/workflows/required.yml",
            )
            validator.validate_consumer(
                root,
                head_sha=head_sha,
                base_sha=base_sha,
                platform_root=ROOT,
            )
        except (ValueError, yaml.YAMLError) as error:
            return subprocess.CompletedProcess(command, 1, "", f"{error}\n")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_required_workflow_identity_rejects_non_main_platform_source() -> None:
    result = _run_required_validator(
        """
on: pull_request
permissions: {contents: read}
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps: [{run: echo safe}]
""",
        platform_ref="refs/heads/feature",
        process_boundary=True,
    )
    assert result.returncode != 0
    assert "runtime identity" in result.stderr


def test_required_integrity_validator_accepts_read_only_pinned_pr_workflow() -> None:
    """Catches a validator that rejects the intended least-privilege shape."""
    result = _run_required_validator(
        """
name: Safe target
on: pull_request
permissions:
  contents: read
jobs:
  verify:
    name: Shadow / verify
    permissions:
      contents: read
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha }}
      - run: python -m compileall -q .
""",
        process_boundary=True,
    )
    assert result.returncode == 0, result.stderr


def test_in_process_validator_calls_isolate_root_head_and_diagnostics() -> None:
    """Catches cached fixture state weakening later in-process validation calls."""
    mutable_nested_action = _run_required_validator(
        """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{uses: ./.github/actions/attack}]
""",
        {
            ".github/actions/attack/action.yml": """
name: Attack
runs:
  using: composite
  steps: [{uses: actions/setup-python@v6}]
"""
        },
        process_boundary=False,
    )
    assert mutable_nested_action.returncode != 0
    assert "mutable nested action reference" in mutable_nested_action.stderr

    safe_workflow = """
on: pull_request
permissions: {contents: read}
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps: [{run: echo safe}]
"""
    invalid_head = _run_required_validator(
        safe_workflow,
        head_sha="c" * 39,
        process_boundary=False,
    )
    assert invalid_head.returncode != 0
    assert "event head is not a full lowercase commit SHA" in invalid_head.stderr
    assert "mutable nested action reference" not in invalid_head.stderr

    clean = _run_required_validator(
        safe_workflow,
        head_sha="c" * 40,
        base_sha="d" * 40,
        process_boundary=False,
    )
    assert clean.returncode == 0
    assert clean.stderr == ""


def test_required_validator_rejects_unmanaged_privileged_deployment() -> None:
    """Privileged workflows require a separately audited closed controller."""
    result = _run_required_validator(
        """
name: Safe deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
    branches: [main]
permissions:
  contents: read
jobs:
  gate:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'push' &&
      github.event.workflow_run.head_branch == 'main'
    runs-on: ubuntu-24.04
    environment: production
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: python -m compileall -q .
  publish-coverage:
    needs: gate
    runs-on: ubuntu-24.04
    environment: production
    steps:
      - uses: actions/download-artifact@95815c38cf2ff2164869cbab79da8d1f422bc89e
        with:
          name: trusted-main-coverage
      - run: echo upload-trusted-main-coverage
"""
    )
    assert result.returncode != 0
    assert "closed controller set" in result.stderr


def test_required_validator_rejects_unguarded_workflow_run_head_execution() -> None:
    result = _run_required_validator(
        """
name: Unsafe follow-up
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-24.04
    environment: production
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: python deploy.py
"""
    )
    assert result.returncode != 0
    assert "closed controller set" in result.stderr


def test_required_validator_rejects_unmanaged_dependabot_followup() -> None:
    result = _run_required_validator(
        """
name: Dependabot follow-up
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: read
  pull-requests: write
jobs:
  arm:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'pull_request'
    runs-on: ubuntu-24.04
    env:
      GH_TOKEN: ${{ secrets.DEPENDABOT_AUTOMERGE_TOKEN }}
    steps:
      - run: gh pr view "${{ github.event.workflow_run.pull_requests[0].number }}"
"""
    )
    assert result.returncode != 0
    assert "closed controller set" in result.stderr


def test_required_integrity_validator_rejects_adversarial_workflows() -> None:
    """Catches permission, secret, context, pin, and trusted-caller weakening."""
    cases = {
        "feature push secret": """
on: push
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    env: {EXFILTRATE: "${{ secrets.REPOSITORY_SECRET }}"}
    steps: [{run: echo attack}]
""",
        "feature push write token": """
on: push
permissions: {contents: write}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "workflow dispatch write": """
on: workflow_dispatch
permissions: {contents: write}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "repository dispatch controller": """
on: repository_dispatch
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "wildcard permissions": """
on: push
permissions: write-all
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "dynamic required context": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    name: "${{ matrix.context }}"
    strategy:
      matrix: {context: ["Security / required"]}
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "privileged env-aliased head": """
on: pull_request_target
permissions: {contents: read}
jobs:
  attack:
    env: {PR_SHA: "${{ github.event.pull_request.head.sha }}"}
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with: {ref: "${{ env.PR_SHA }}"}
""",
        "privileged always after weak guard": """
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions: {contents: read}
jobs:
  weak:
    if: github.event.workflow_run.conclusion != 'success' || github.event.workflow_run.event != 'push'
    runs-on: ubuntu-24.04
    steps: [{run: echo weak}]
  attack:
    needs: weak
    if: always()
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "write permission": """
on: pull_request
permissions: {contents: write}
jobs: {attack: {runs-on: ubuntu-24.04, steps: [{run: echo attack}]}}
""",
        "implicit permissions": """
on: pull_request
jobs: {attack: {runs-on: ubuntu-24.04, steps: [{run: echo attack}]}}
""",
        "OIDC": """
on: pull_request
permissions: {contents: read, id-token: write}
jobs: {attack: {runs-on: ubuntu-24.04, steps: [{run: echo attack}]}}
""",
        "secret": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    env: {TOKEN: "${{ secrets.DEPLOY_TOKEN }}"}
    steps: [{run: echo attack}]
""",
        "secret JSON": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    env: {ALL_SECRETS: "${{ toJSON(secrets) }}"}
    steps: [{run: echo attack}]
""",
        "bracket token": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    env: {GH_TOKEN: "${{ github['token'] }}"}
    steps: [{run: gh api repos/example/example/check-runs}]
""",
        "protected environment": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    environment: production
    runs-on: ubuntu-24.04
    steps: [{run: echo attack}]
""",
        "secret inheritance": """
on: workflow_call
jobs:
  attack:
    uses: koios-ai/ci-platform/.github/workflows/reusable-final.yml@dddddddddddddddddddddddddddddddddddddddd
    secrets: inherit
""",
        "mutable action": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{uses: actions/checkout@v4}]
""",
        "required context spoof": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    name: AI / Codex final
    runs-on: ubuntu-24.04
    steps: [{run: echo pass}]
""",
        "expression context spoof": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    name: "${{ 'CI / required' }}"
    runs-on: ubuntu-24.04
    steps: [{run: echo pass}]
""",
        "partial expression context spoof": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    name: "CI / ${{ 'required' }}"
    runs-on: ubuntu-24.04
    steps: [{run: echo pass}]
""",
        "weakened final caller": """
on: pull_request_target
permissions: {contents: read}
jobs:
  final:
    permissions: {contents: read}
    uses: koios-ai/ci-platform/.github/workflows/reusable-final.yml@dddddddddddddddddddddddddddddddddddddddd
    with: {head_sha: "${{ github.event.pull_request.head.sha }}"}
""",
        "PR-target head checkout": """
on: pull_request_target
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
""",
        "PR-target shell head fetch": """
on: pull_request_target
permissions: {contents: write, id-token: write}
jobs:
  attack:
    environment: production
    runs-on: ubuntu-24.04
    steps:
      - run: |
          git fetch origin refs/pull/${{ github.event.pull_request.number }}/head
          git checkout FETCH_HEAD
          bash .github/scripts/deploy.sh
""",
        "workflow-run head checkout": """
on: workflow_run
permissions: {contents: write, id-token: write}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with: {ref: "${{ github.event.workflow_run.head_sha }}"}
""",
        "untrusted cache": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with: {path: ., key: shared-default-cache}
""",
        "untrusted artifact execution": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0
      - run: bash artifact/run.sh
""",
        "privileged arbitrary publisher action": """
on:
  pull_request_target:
    types: [labeled]
permissions: {}
jobs:
  attack:
    permissions: {checks: write, contents: read, pull-requests: read}
    runs-on: ubuntu-24.04
    env:
      CI_PLATFORM_ROLE: ai-context-publisher
      GH_TOKEN: "${{ github.token }}"
    steps:
      - uses: attacker/check-publisher@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
        "privileged local reusable bridge": """
on:
  pull_request_target:
    types: [labeled]
permissions: {}
jobs:
  attack:
    permissions: {contents: write}
    uses: ./.github/workflows/attack.yml
    env:
      CI_PLATFORM_ROLE: metadata-controller
""",
        "review requester all secrets": """
on:
  pull_request_target:
    types: [labeled]
permissions: {}
jobs:
  attack:
    permissions: {contents: read, pull-requests: write}
    runs-on: ubuntu-24.04
    env:
      CI_PLATFORM_ROLE: review-requester
      ALL_SECRETS: "${{ toJSON(secrets) }}"
    steps:
      - uses: attacker/reviewer@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
        "required check API minting": """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    env: {GH_TOKEN: "${{ github['token'] }}"}
    steps:
      - run: gh api --method POST repos/example/example/check-runs -f name='CI / required'
""",
        "required context via external reusable workflow": """
on: pull_request
permissions: {contents: read}
jobs:
  spoof:
    name: CI
    permissions: {contents: read}
    uses: attacker/repository/.github/workflows/pass.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
    }
    for name, workflow in cases.items():
        result = _run_required_validator(workflow)
        assert result.returncode != 0, name
        assert result.stderr.strip(), name


def test_required_integrity_validator_rejects_mutable_nested_action() -> None:
    """Catches a mutable supply-chain edge hidden behind a local action."""
    result = _run_required_validator(
        """
on: pull_request
permissions: {contents: read}
jobs:
  attack:
    runs-on: ubuntu-24.04
    steps: [{uses: ./.github/actions/attack}]
""",
        {
            ".github/actions/attack/action.yml": """
name: Attack
runs:
  using: composite
  steps: [{uses: actions/setup-python@v6}]
"""
        },
    )
    assert result.returncode != 0
    assert "mutable nested action reference" in result.stderr


def test_required_integrity_validator_rejects_forged_final_inputs() -> None:
    """Catches base-as-head, forced-baseline, and fabricated digest evidence."""
    pin = "d" * 40
    result = _run_required_validator(
        f"""
on:
  pull_request_target:
    types: [labeled]
permissions: {{contents: read}}
jobs:
  final:
    permissions: {{contents: read}}
    uses: koios-ai/ci-platform/.github/workflows/reusable-final.yml@{pin}
    with:
      profile: baseline
      head_sha: "${{{{ github.event.pull_request.base.sha }}}}"
      base_sha: "${{{{ github.event.pull_request.base.sha }}}}"
      changed_files_digest: "{"0" * 64}"
      python_version: "3.12"
      artifact_retention_days: 3
""",
        {".github/ci-platform.lock.json": json.dumps({"sha": pin, "contract_version": 1})},
    )
    assert result.returncode != 0
    assert result.stderr.strip()


def test_required_integrity_validator_rejects_case_variant_platform_prefix() -> None:
    """Catches bypassing the platform allowlist with owner/repo case changes."""
    pin = "d" * 40
    result = _run_required_validator(
        f"""
on:
  pull_request_target:
    types: [labeled]
permissions: {{contents: read}}
jobs:
  final:
    permissions: {{contents: read}}
    uses: KOIOS-AI/CI-PLATFORM/.github/workflows/reusable-final.yml@{pin}
    with:
      profile: "${{{{ needs.final-preflight.outputs.profile }}}}"
      head_sha: "${{{{ needs.final-preflight.outputs.head_sha }}}}"
      base_sha: "${{{{ needs.final-preflight.outputs.base_sha }}}}"
      changed_files_digest: "${{{{ needs.final-preflight.outputs.changed_files_digest }}}}"
      python_version: "3.12"
      artifact_retention_days: 3
""",
        {".github/ci-platform.lock.json": json.dumps({"sha": pin, "contract_version": 1})},
    )
    assert result.returncode != 0
    assert result.stderr.strip()


def test_required_integrity_validator_rejects_platform_role_outside_managed_path() -> None:
    """Catches reserved controller roles escaping the exact managed tree."""
    pin = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    result = _run_required_validator(
        f"""
on:
  pull_request_target:
    types: [synchronize]
permissions: {{}}
jobs:
  invalidate:
    permissions:
      issues: write
      pull-requests: read
    runs-on: ubuntu-24.04
    env:
      CI_PLATFORM_ROLE: label-controller
      GH_TOKEN: "${{{{ github.token }}}}"
    steps:
      - uses: koios-ai/ci-platform/.github/actions/invalidate-final-labels@{pin}
        with:
          pull_request_number: "${{{{ github.event.pull_request.number }}}}"
          event_head_sha: "${{{{ github.event.pull_request.head.sha }}}}"
""",
        {".github/ci-platform.lock.json": json.dumps({"sha": pin, "contract_version": 1})},
    )
    assert result.returncode != 0
    assert "closed controller set" in result.stderr


def test_required_integrity_validator_accepts_exact_trusted_final_topology() -> None:
    """Catches over-specific hardening that blocks the migrated consumer."""
    pin = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()

    def rendered(name: str) -> str:
        return (CONSUMER_WORKFLOWS / name).read_text(encoding="utf-8").replace("__CI_PLATFORM_FULL_SHA__", pin)

    result = _run_required_validator(
        rendered("final-required.yml"),
        {
            ".github/workflows/coderabbit-final.yml": rendered("coderabbit-final.yml"),
            ".github/workflows/codex-final-gate.yml": rendered("codex-final-gate.yml"),
            ".github/workflows/ai-findings-resolved.yml": rendered("ai-findings-resolved.yml"),
            ".github/workflows/invalidate-final-labels.yml": rendered("invalidate-final-labels.yml"),
            ".github/workflows/final-subject-v1.yml": rendered("final-subject-v1.yml"),
            ".github/workflows/finalize-python-v1.yml": rendered("finalize-python-v1.yml"),
            ".github/workflows/resume-finalizer-v1.yml": rendered("resume-finalizer-v1.yml"),
            ".github/ci/evaluate_ai_provider.py": (
                ROOT / "templates" / "consumer" / ".github" / "ci" / "evaluate_ai_provider.py"
            ).read_text(encoding="utf-8"),
            ".github/ci-platform.lock.json": json.dumps({"sha": pin, "contract_version": 1}),
            ".github/ci-platform-test-policy.json": json.dumps(BASELINE_TEST_POLICY),
            ".coderabbit.yaml": (ROOT / "templates" / "consumer" / ".coderabbit.yaml").read_text(encoding="utf-8"),
        },
        workflow_name="final-required.yml",
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("instance", "valid"),
    [
        (
            {
                "profile": "baseline",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "changed_files_digest": "c" * 64,
                "python_version": "3.12",
                "artifact_retention_days": 3,
            },
            True,
        ),
        (
            {
                "profile": "unknown",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "changed_files_digest": "c" * 64,
                "python_version": "3.12",
                "artifact_retention_days": 3,
            },
            False,
        ),
        (
            {
                "profile": "python",
                "head_sha": "short",
                "base_sha": "b" * 40,
                "changed_files_digest": "c" * 64,
                "python_version": "3.12",
                "artifact_retention_days": 8,
            },
            False,
        ),
    ],
)
def test_contract_examples_accept_only_the_closed_boundary(instance: dict[str, Any], valid: bool) -> None:
    """Catches schema drift by exercising representative caller payloads."""
    contract = load_contract()
    properties = contract["properties"]
    observed = (
        set(instance) == set(contract["required"])
        and instance["profile"] in properties["profile"]["enum"]
        and re.fullmatch(properties["head_sha"]["pattern"], instance["head_sha"]) is not None
        and re.fullmatch(properties["base_sha"]["pattern"], instance["base_sha"]) is not None
        and re.fullmatch(
            properties["changed_files_digest"]["pattern"],
            instance["changed_files_digest"],
        )
        is not None
        and properties["artifact_retention_days"]["minimum"]
        <= instance["artifact_retention_days"]
        <= properties["artifact_retention_days"]["maximum"]
    )
    assert observed is valid
