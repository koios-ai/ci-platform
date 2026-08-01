from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event
from types import ModuleType
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "koios_ci.py"
SCHEMA = ROOT / "contract" / "finalizer-status-v1.schema.json"

HEAD = "a" * 40
NEW_HEAD = "b" * 40
BASE = "c" * 40
PLATFORM_SHA = "d" * 40
CONTROLLER_SHA = BASE
REPOSITORY = "koios-ai/example"
WORKFLOW_ID = 71234
CONTROLLER_WORKFLOW_ID = 81234
WORKFLOW_PATH = ".github/workflows/merge-gate-python-v1.yml"
CONTROLLER_WORKFLOW_PATH = ".github/workflows/finalize-python-v1.yml"
SOURCE_PATH = "koios-ai/ci-platform/.github/workflows/merge-gate-python-v1.yml@" + PLATFORM_SHA
SUBJECT_RUN_ID = 100
CONTROLLER_RUN_ID = 900
PROMOTER: dict[str, Any] = {
    "login": "github-actions[bot]",
    "id": 41898282,
    "type": "Bot",
}


def load_module(name: str = "koios_ci") -> ModuleType:
    assert SCRIPT.exists(), "Task 3 finalizer has not been implemented"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def provider_snapshot(
    *,
    head_sha: str = HEAD,
    unresolved: bool = False,
) -> dict[str, Any]:
    identities = (
        ("coderabbit", "coderabbitai[bot]", 347564, "coderabbitai"),
        (
            "codex",
            "chatgpt-codex-connector[bot]",
            1144995,
            "chatgpt-codex-connector",
        ),
    )
    reviews = []
    issue_comments: list[dict[str, Any]] = []
    review_comments: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    for offset, (provider, login, app_id, app_slug) in enumerate(identities, 1):
        reviews.append(
            {
                "id": 10 + offset,
                "user": {"login": login},
                "commit_id": head_sha,
                "state": "COMMENTED",
                "body": "PASS" if provider == "codex" else "coderabbit native review completed for the current head",
                "submitted_at": f"2026-07-27T10:0{offset}:00Z",
            }
        )
        destination = issue_comments if provider == "coderabbit" else review_comments
        destination.append(
            {
                "id": 20 + offset,
                "user": {"login": login},
                "performed_via_github_app": {"id": app_id, "slug": app_slug},
                "body": f"{provider} native delivery completed with no unresolved findings",
                "updated_at": f"2026-07-27T10:1{offset}:00Z",
            }
        )
        if provider == "coderabbit":
            checks.append(
                {
                    "id": 30 + offset,
                    "name": "CodeRabbit",
                    "head_sha": head_sha,
                    "status": "completed",
                    "conclusion": "success",
                    "app": {"id": app_id, "slug": app_slug},
                    "started_at": "2026-07-27T10:00:00Z",
                    "completed_at": "2026-07-27T10:20:00Z",
                    "output": {
                        "title": "CodeRabbit review",
                        "summary": "Review completed",
                        "text": "",
                    },
                }
            )
    thread_nodes: list[dict[str, Any]] = []
    if unresolved:
        thread_nodes.append(
            {
                "isResolved": False,
                "comments": {
                    "nodes": [{"author": {"login": "coderabbitai[bot]"}}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                },
            }
        )
    return {
        "readback": "complete",
        "reviews": reviews,
        "issue_comments": issue_comments,
        "review_comments": review_comments,
        "checks": checks,
        "threads": {
            "nodes": thread_nodes,
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": None,
            },
        },
    }


def pull(
    *,
    head_sha: str = HEAD,
    base_sha: str = BASE,
    author: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "number": 42,
        "state": "open",
        "draft": False,
        "changed_files": 1,
        "commits": 1,
        "user": author or {"login": "octocat", "id": 1, "type": "User"},
        "head": {
            "sha": head_sha,
            "repo": {"id": 123, "full_name": REPOSITORY},
        },
        "base": {
            "sha": base_sha,
            "ref": "main",
            "repo": {"id": 123, "full_name": REPOSITORY},
        },
    }


def run(
    *,
    run_id: int = SUBJECT_RUN_ID,
    attempt: int = 1,
    conclusion: str | None = "success",
    status: str = "completed",
    head_sha: str = CONTROLLER_SHA,
    workflow_id: int = WORKFLOW_ID,
    workflow_path: str = WORKFLOW_PATH,
    source_path: str = SOURCE_PATH,
    source_sha: str = PLATFORM_SHA,
    created_at: str = "2026-07-27T10:00:00Z",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": workflow_id,
        "path": workflow_path,
        "head_sha": head_sha,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "display_title": (f"koios-final-subject-v1|repo=123|pr=42|head={HEAD}|base={BASE}|platform={PLATFORM_SHA}"),
        "actor": {**PROMOTER, "avatar_url": "https://avatars.example/actions"},
        "triggering_actor": {
            **PROMOTER,
            "avatar_url": "https://avatars.example/actions",
        },
        "referenced_workflows": [
            {
                "path": source_path,
                "sha": source_sha,
            }
        ],
        "status": status,
        "conclusion": conclusion,
        "created_at": created_at,
        "updated_at": created_at,
    }


def controller_run(
    *,
    run_id: int = CONTROLLER_RUN_ID,
    attempt: int = 1,
    conclusion: str | None = None,
    status: str = "in_progress",
    head_sha: str = CONTROLLER_SHA,
    workflow_id: int = CONTROLLER_WORKFLOW_ID,
    workflow_path: str = CONTROLLER_WORKFLOW_PATH,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": workflow_id,
        "path": workflow_path,
        "head_sha": head_sha,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "display_title": (
            f"koios-finalizer-v1|repo=123|pr=42|head={HEAD}|base={BASE}|subject={SUBJECT_RUN_ID}|attempt=1"
        ),
        "actor": {**PROMOTER, "avatar_url": "https://avatars.example/actions"},
        "triggering_actor": {
            **PROMOTER,
            "avatar_url": "https://avatars.example/actions",
        },
        "referenced_workflows": [],
        "status": status,
        "conclusion": conclusion,
        "created_at": "2026-07-27T10:30:00Z",
        "updated_at": "2026-07-27T10:30:00Z",
    }


def jobs(
    *,
    run_id: int = 100,
    attempt: int = 1,
    conclusion: str = "success",
) -> dict[str, Any]:
    rows = [
        {
            "id": 200 + index,
            "name": name,
            "status": "completed",
            "conclusion": conclusion,
        }
        for index, name in enumerate(
            (
                "Immutable platform final subject / Platform / deterministic final evidence",
                "Immutable platform final subject / Platform / security evidence",
                "Immutable platform final subject / Platform / coverage evidence verification",
            ),
            start=1,
        )
    ]
    return {
        "run_id": run_id,
        "run_attempt": attempt,
        "total_count": len(rows),
        "jobs": rows,
    }


class FakeAPI:
    def __init__(
        self,
        *,
        pulls: list[dict[str, Any]] | None = None,
        runs: list[dict[str, Any]] | None = None,
        jobs_payload: dict[str, Any] | None = None,
        snapshot: dict[str, Any] | Exception | None = None,
        run_inventory: dict[str, Any] | None = None,
    ) -> None:
        self.repository = {
            "id": 123,
            "full_name": REPOSITORY,
            "default_branch": "main",
        }
        self.pulls = pulls or [pull()]
        self.controller_runs = [controller_run()]
        self.runs = runs or [run()]
        self.jobs_payload = jobs_payload if jobs_payload is not None else jobs()
        self.advance_run_after_jobs: dict[str, Any] | None = None
        self.snapshot = snapshot if snapshot is not None else provider_snapshot()
        self.labels: list[tuple[str, int, tuple[str, ...]]] = []
        self.live_labels: set[str] = set()
        self.label_mode = "normal"
        self.label_error: Exception | None = None
        self.removed_labels: list[str] = []
        self.reruns: list[tuple[str, int, int]] = []
        self.pull_reads = 0
        self.provider_reads = 0
        self.advance_head_after_provider = False
        self.remove_labels_after_provider = False
        self.source_attestation: dict[str, Any] = {
            "readback": "complete",
            "schema_version": "koios-run-source-v3",
            "repository_id": 123,
            "pull_request": 42,
            "pr_head_sha": HEAD,
            "base_sha": BASE,
            "controller_run_id": CONTROLLER_RUN_ID,
            "controller_run_attempt": 1,
            "controller_workflow_id": CONTROLLER_WORKFLOW_ID,
            "controller_path": CONTROLLER_WORKFLOW_PATH,
            "controller_sha": CONTROLLER_SHA,
            "controller_ref": "refs/heads/main",
            "controller_event": "workflow_dispatch",
            "subject_run_id": SUBJECT_RUN_ID,
            "subject_run_attempt": 1,
            "subject_workflow_id": WORKFLOW_ID,
            "subject_path": WORKFLOW_PATH,
            "subject_sha": CONTROLLER_SHA,
            "authored_source_selector": SOURCE_PATH,
            "resolved_source_sha": PLATFORM_SHA,
            "source_path": SOURCE_PATH,
            "source_sha": PLATFORM_SHA,
            "promoter": PROMOTER,
        }
        self.run_inventory = run_inventory or {
            "readback": "complete",
            "repository_id": 123,
            "pull_request": 42,
            "head_sha": HEAD,
            "base_sha": BASE,
            "workflow_id": WORKFLOW_ID,
            "selected_run_id": SUBJECT_RUN_ID,
            "selected_attempt": 1,
            "platform_sha": PLATFORM_SHA,
            "runs": [
                {
                    "id": SUBJECT_RUN_ID,
                    "attempt": 1,
                    "workflow_id": WORKFLOW_ID,
                    "display_title": (
                        f"koios-final-subject-v1|repo=123|pr=42|head={HEAD}|base={BASE}|platform={PLATFORM_SHA}"
                    ),
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-07-27T10:00:00Z",
                    "updated_at": "2026-07-27T10:04:00Z",
                    "total_jobs": 3,
                }
            ],
        }

    def get_repository(self, repository: str) -> dict[str, Any]:
        assert repository == REPOSITORY
        return self.repository

    def get_pull(self, repository: str, number: int) -> dict[str, Any]:
        assert repository == REPOSITORY
        assert number == 42
        value = self.pulls[min(self.pull_reads, len(self.pulls) - 1)]
        self.pull_reads += 1
        return value

    def get_workflow_run(self, repository: str, run_id: int) -> dict[str, Any]:
        assert repository == REPOSITORY
        rows = self.controller_runs if run_id == CONTROLLER_RUN_ID else self.runs
        matches = [item for item in rows if item["id"] == run_id]
        return max(matches, key=lambda item: item["run_attempt"])

    def list_run_jobs(
        self,
        repository: str,
        run_id: int,
        attempt: int,
    ) -> dict[str, Any]:
        assert repository == REPOSITORY
        result = self.jobs_payload
        if self.advance_run_after_jobs is not None:
            self.runs.append(self.advance_run_after_jobs)
            self.advance_run_after_jobs = None
        return result

    def rerun_failed_jobs(
        self,
        repository: str,
        run_id: int,
        attempt: int,
    ) -> None:
        self.reruns.append((repository, run_id, attempt))

    def get_run_source_attestation(
        self,
        repository: str,
        number: int,
        head_sha: str,
        base_sha: str,
        controller_run_id: int,
        controller_attempt: int,
        subject_run_id: int,
        subject_attempt: int,
    ) -> dict[str, Any]:
        return self.source_attestation

    def list_same_head_run_inventory(
        self,
        repository: str,
        number: int,
        head_sha: str,
        base_sha: str,
        workflow_id: int,
        selected_run_id: int,
        selected_attempt: int,
        platform_sha: str,
    ) -> dict[str, Any]:
        return self.run_inventory

    def add_labels(
        self,
        repository: str,
        number: int,
        labels: tuple[str, ...],
    ) -> None:
        self.labels.append((repository, number, labels))
        if self.label_mode == "normal":
            self.live_labels.update(labels)
        elif self.label_mode == "partial":
            self.live_labels.add(labels[0])
        elif self.label_mode == "partial-ai":
            self.live_labels.add(labels[-1])
        elif self.label_mode == "timeout-after-write":
            self.live_labels.update(labels)
        if self.label_error is not None:
            raise self.label_error

    def get_pull_labels(self, repository: str, number: int) -> set[str]:
        return set(self.live_labels)

    def remove_label(self, repository: str, number: int, label: str) -> None:
        self.live_labels.discard(label)
        self.removed_labels.append(label)

    def provider_snapshot(
        self,
        repository: str,
        number: int,
        head_sha: str,
    ) -> dict[str, Any]:
        assert repository == REPOSITORY
        assert number == 42
        assert head_sha == HEAD
        self.provider_reads += 1
        if self.remove_labels_after_provider:
            self.live_labels.clear()
            self.remove_labels_after_provider = False
        if self.advance_head_after_provider:
            self.pulls.append(pull(head_sha=NEW_HEAD))
            self.advance_head_after_provider = False
        if isinstance(self.snapshot, Exception):
            raise self.snapshot
        return self.snapshot


def make_finalizer(
    module: ModuleType,
    tmp_path: Path,
    api: FakeAPI,
    *,
    provider_contract_verified: bool = True,
    codex_hosted_canary_verified: bool = True,
    invalidation_controller_verified: bool = True,
    latest_run_inventory_verified: bool = True,
    external_singleflight_verified: bool = True,
    controller_sha: str = CONTROLLER_SHA,
) -> Any:
    config = module.FinalizerConfig(
        workflow=module.WorkflowIdentity(
            workflow_id=WORKFLOW_ID,
            path=WORKFLOW_PATH,
            sha=PLATFORM_SHA,
            event="workflow_dispatch",
            source_path=SOURCE_PATH,
            promoter=PROMOTER,
        ),
        controller=module.ControllerIdentity(
            path=CONTROLLER_WORKFLOW_PATH,
            event="workflow_dispatch",
            repository=REPOSITORY,
            repository_id=123,
            run_id=CONTROLLER_RUN_ID,
            run_attempt=1,
            sha=controller_sha,
            ref="refs/heads/main",
        ),
        subject_run_id=SUBJECT_RUN_ID,
        subject_run_attempt=1,
        provider_contract_verified=provider_contract_verified,
        codex_hosted_canary_verified=codex_hosted_canary_verified,
        invalidation_controller_verified=invalidation_controller_verified,
        latest_run_inventory_verified=latest_run_inventory_verified,
        external_singleflight_verified=external_singleflight_verified,
    )
    return module.Finalizer(api=api, state_dir=tmp_path, config=config)


def blocker_codes(result: dict[str, Any]) -> set[str]:
    return {item["code"] for item in result["blockers"]}


def test_task3_finalizer_exists() -> None:
    assert SCRIPT.exists()


def test_success_is_exact_head_bound_and_resume_is_idempotent(tmp_path: Path) -> None:
    module = load_module()
    api = FakeAPI()
    finalizer = make_finalizer(module, tmp_path, api)

    first = finalizer.finalize(REPOSITORY, 42)
    second = finalizer.resume(REPOSITORY, 42, HEAD)

    assert first["complete"] is True
    assert first["phase"] == "complete"
    assert second["complete"] is True
    assert second["key"] == first["key"]
    assert api.labels == [
        (REPOSITORY, 42, ("ci-final", "ai-review-ready")),
    ]
    assert len(list(tmp_path.glob("*.json"))) == 1
    module.validate_state(first)


def test_concurrent_finalizer_cannot_remove_successful_writers_labels(
    tmp_path: Path,
) -> None:
    """The exact-head operation lease must cover labels through durable state."""
    module = load_module("koios_ci_external_mutation_singleflight")

    class BlockingProviderAPI(FakeAPI):
        provider_started = Event()
        release_provider = Event()

        def provider_snapshot(
            self,
            repository: str,
            number: int,
            head_sha: str,
        ) -> dict[str, Any]:
            self.provider_started.set()
            if not self.release_provider.wait(timeout=10):
                raise RuntimeError("test did not release provider readback")
            return super().provider_snapshot(repository, number, head_sha)

    api = BlockingProviderAPI()
    winner = make_finalizer(module, tmp_path, api)
    contender = make_finalizer(module, tmp_path, api)
    with ThreadPoolExecutor(max_workers=2) as executor:
        future = executor.submit(winner.finalize, REPOSITORY, 42)
        assert api.provider_started.wait(timeout=10)
        try:
            contender_result = contender.finalize(REPOSITORY, 42)
        finally:
            api.release_provider.set()
        winner_result = future.result(timeout=10)

    assert winner_result["complete"] is True
    assert contender_result["complete"] is False
    assert "state-operation-conflict" in blocker_codes(contender_result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []
    assert not list(tmp_path.glob("*.operation.lock"))


def test_mutation_lease_rechecks_state_observed_before_competing_writer(
    tmp_path: Path,
) -> None:
    """A stale observer must stop before touching labels after it wins the lease."""
    module = load_module("koios_ci_operation_lease_stale_observer")
    api = FakeAPI()
    stale_writer = make_finalizer(module, tmp_path, api)
    winner = make_finalizer(module, tmp_path, api)
    repository_payload, pull_payload = stale_writer._read_boundary(REPOSITORY, 42)
    stale_state = stale_writer._initial_state(
        REPOSITORY,
        42,
        repository_payload,
        pull_payload,
        dry_run=False,
    )

    winner_result = winner.finalize(REPOSITORY, 42)
    stale_result = stale_writer._execute_serialized(
        stale_state,
        pull_payload,
        rerun_failed=False,
        timeout_seconds=0,
        poll_seconds=1,
    )

    assert winner_result["complete"] is True
    assert stale_result["complete"] is False
    assert "state-operation-stale-observation" in blocker_codes(stale_result)
    assert api.labels == [(REPOSITORY, 42, ("ci-final", "ai-review-ready"))]
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_head_change_before_label_mutation_fails_closed(tmp_path: Path) -> None:
    module = load_module("koios_ci_stale_head")
    api = FakeAPI(pulls=[pull(), pull(head_sha=NEW_HEAD)])
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "pull-head-changed" in blocker_codes(result)
    assert api.labels == []


def test_base_change_before_label_mutation_fails_closed(tmp_path: Path) -> None:
    module = load_module("koios_ci_stale_base")
    api = FakeAPI(pulls=[pull(), pull(base_sha=NEW_HEAD)])
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "pull-base-changed" in blocker_codes(result)
    assert api.labels == []


def test_current_controller_attempt_cannot_be_replaced_by_newer_attempt(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_newer_attempt")
    api = FakeAPI(
        runs=[
            run(run_id=100, attempt=1, conclusion="success"),
            run(
                run_id=100,
                attempt=2,
                conclusion="startup_failure",
                created_at="2026-07-27T10:05:00Z",
            ),
        ]
    )
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "wrong-subject-run-attempt" in blocker_codes(result)
    assert result["subject_run"] is None
    assert api.labels == []


@pytest.mark.parametrize(
    ("changed", "expected"),
    (
        ({"workflow_id": 999}, "wrong-workflow-identity"),
        ({"path": ".github/workflows/attacker.yml"}, "wrong-workflow-identity"),
        (
            {
                "referenced_workflows": [
                    {
                        "path": SOURCE_PATH,
                        "sha": "e" * 40,
                        "ref": "e" * 40,
                    }
                ]
            },
            "wrong-workflow-identity",
        ),
        ({"head_sha": NEW_HEAD}, "source-provenance-invalid"),
    ),
)
def test_wrong_workflow_identity_or_source_head_never_promotes(
    tmp_path: Path,
    changed: dict[str, Any],
    expected: str,
) -> None:
    module = load_module(f"koios_ci_wrong_{next(iter(changed))}")
    api = FakeAPI(runs=[{**run(), **changed}])
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert expected in blocker_codes(result)
    assert api.labels == []


def test_documented_rest_run_shapes_are_accepted() -> None:
    """Rejecting GitHub's documented path/ref shape must fail this test."""
    module = load_module("koios_ci_documented_rest_shape")
    workflow = module.WorkflowIdentity(
        workflow_id=WORKFLOW_ID,
        path=WORKFLOW_PATH,
        sha=PLATFORM_SHA,
        event="workflow_dispatch",
        source_path=SOURCE_PATH,
        promoter=PROMOTER,
    )
    payload = run(workflow_path=WORKFLOW_PATH)
    payload["referenced_workflows"][0].pop("ref", None)

    assert (
        module._validate_subject_run_identity(
            payload,
            workflow,
            SUBJECT_RUN_ID,
            1,
            "refs/heads/main",
        )
        is None
    )


def test_default_branch_controller_sha_is_separate_from_pr_head(
    tmp_path: Path,
) -> None:
    """Comparing controller SHA to PR head must fail this test."""
    module = load_module("koios_ci_controller_sha")
    api = FakeAPI(runs=[run(head_sha=CONTROLLER_SHA)])

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is True


@pytest.mark.parametrize("source", ["controller", "subject"])
def test_controller_and_subject_source_sha_must_equal_the_exact_pr_base(
    tmp_path: Path,
    source: str,
) -> None:
    module = load_module(f"koios_ci_source_base_{source}")
    api = FakeAPI()
    controller_sha = CONTROLLER_SHA
    if source == "controller":
        controller_sha = NEW_HEAD
        api.controller_runs[0]["head_sha"] = NEW_HEAD
        api.source_attestation["controller_sha"] = NEW_HEAD
    else:
        api.runs = [run(head_sha=NEW_HEAD)]
        api.source_attestation["subject_sha"] = NEW_HEAD

    result = make_finalizer(
        module,
        tmp_path,
        api,
        controller_sha=controller_sha,
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "source-provenance-invalid" in blocker_codes(result)


def test_zero_job_run_is_not_recovery(tmp_path: Path) -> None:
    module = load_module("koios_ci_zero_jobs")
    api = FakeAPI(
        jobs_payload={
            "run_id": 100,
            "run_attempt": 1,
            "total_count": 0,
            "jobs": [],
        }
    )
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert "workflow-zero-jobs" in blocker_codes(result)
    assert api.labels == []


def test_unverified_latest_run_inventory_blocks_older_success_selection(
    tmp_path: Path,
) -> None:
    """An explicit old run cannot authorize while a newer run may exist."""
    module = load_module("koios_ci_latest_run_inventory")
    api = FakeAPI()
    api.run_inventory["runs"].append(
        {
            "id": SUBJECT_RUN_ID + 1,
            "attempt": 1,
            "workflow_id": WORKFLOW_ID,
            "display_title": (f"koios-final-subject-v1|repo=123|pr=42|head={HEAD}|base={BASE}|platform={PLATFORM_SHA}"),
            "status": "completed",
            "conclusion": "startup_failure",
            "created_at": "2026-07-27T10:05:00Z",
            "updated_at": "2026-07-27T10:05:00Z",
            "total_jobs": 0,
        }
    )

    result = make_finalizer(
        module,
        tmp_path,
        api,
        latest_run_inventory_verified=True,
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "newer-same-head-run-attempt" in blocker_codes(result)
    assert api.labels == []


def test_unverified_hosted_singleflight_blocks_before_label_mutation(
    tmp_path: Path,
) -> None:
    """A local file lease is not proof of serialization across hosted runners."""
    module = load_module("koios_ci_external_singleflight")
    api = FakeAPI()

    result = make_finalizer(
        module,
        tmp_path,
        api,
        external_singleflight_verified=False,
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "external-singleflight-unverified" in blocker_codes(result)
    assert api.labels == []


@pytest.mark.parametrize(
    ("reason", "expected"),
    (
        ("rate-limit", "provider-rate-limit"),
        ("quota", "provider-quota-exhausted"),
        ("outage", "provider-outage"),
    ),
)
def test_provider_rate_limit_quota_and_outage_fail_closed(
    tmp_path: Path,
    reason: str,
    expected: str,
) -> None:
    module = load_module(f"koios_ci_provider_{reason}")
    error = module.ProviderUnavailable(reason)
    api = FakeAPI(snapshot=error)
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert expected in blocker_codes(result)
    assert api.labels == [
        (REPOSITORY, 42, ("ci-final", "ai-review-ready")),
    ]
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_unresolved_provider_thread_fails_closed(tmp_path: Path) -> None:
    module = load_module("koios_ci_unresolved")
    api = FakeAPI(snapshot=provider_snapshot(unresolved=True))
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "unresolved-review-threads" in blocker_codes(result)


def test_malformed_unresolved_provider_thread_fails_closed(
    tmp_path: Path,
) -> None:
    """Missing closed thread fields must never be treated as resolved."""
    module = load_module("koios_ci_malformed_thread")
    snapshot = provider_snapshot()
    snapshot["threads"] = [{"isResolved": False, "comments": {}}]

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(snapshot=snapshot),
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-malformed" in blocker_codes(result)


def test_newer_stale_provider_review_never_mints_pass(tmp_path: Path) -> None:
    module = load_module("koios_ci_provider_newer_stale_head")
    snapshot = provider_snapshot()
    coderabbit_reviews = [item for item in snapshot["reviews"] if item["user"]["login"] == "coderabbitai[bot]"]
    coderabbit_reviews.append(
        {
            "id": 99,
            "user": {"login": "coderabbitai[bot]"},
            "commit_id": NEW_HEAD,
            "state": "COMMENTED",
            "body": "CodeRabbit native review completed on a stale head",
            "submitted_at": "2026-07-27T10:59:00Z",
        }
    )
    snapshot["reviews"].append(coderabbit_reviews[-1])
    result = make_finalizer(module, tmp_path, FakeAPI(snapshot=snapshot)).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "coderabbit-evidence-invalid" in blocker_codes(result)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("skipped", "coderabbit-evidence-invalid"),
        ("wrong-app", "coderabbit-evidence-invalid"),
        ("duplicate", "provider-evidence-malformed"),
        ("malformed-output", "provider-evidence-malformed"),
        ("rate-limited", "provider-rate-limit"),
    ],
)
def test_coderabbit_native_check_fails_closed_on_non_success_or_malformed_evidence(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    snapshot = provider_snapshot()
    check = snapshot["checks"][0]
    if mutation == "skipped":
        check["conclusion"] = "skipped"
    elif mutation == "wrong-app":
        check["app"] = {"id": 1, "slug": "attacker"}
    elif mutation == "duplicate":
        snapshot["checks"].append(copy.deepcopy(check))
    elif mutation == "malformed-output":
        check["output"] = "not-an-object"
    else:
        check["output"]["summary"] = "Rate limit reached"
    module = load_module(f"koios_ci_native_check_{mutation}")

    result = make_finalizer(module, tmp_path, FakeAPI(snapshot=snapshot)).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert expected in blocker_codes(result)


def test_historical_provider_quota_message_does_not_poison_current_head_pass(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_historical_quota")
    snapshot = provider_snapshot()
    snapshot["reviews"].append(
        {
            "id": 1,
            "user": {"login": "coderabbitai[bot]"},
            "commit_id": "e" * 40,
            "state": "COMMENTED",
            "body": "Usage limit reached on an obsolete head",
            "submitted_at": "2026-07-26T10:00:00Z",
        }
    )

    result = make_finalizer(module, tmp_path, FakeAPI(snapshot=snapshot)).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is True


def test_current_provider_quota_message_fails_closed(tmp_path: Path) -> None:
    module = load_module("koios_ci_current_quota")
    snapshot = provider_snapshot()
    current = next(item for item in snapshot["reviews"] if item["user"]["login"] == "coderabbitai[bot]")
    current["body"] = "Usage limit reached"

    result = make_finalizer(module, tmp_path, FakeAPI(snapshot=snapshot)).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "provider-quota-exhausted" in blocker_codes(result)


@pytest.mark.parametrize("provider", ["coderabbit", "codex"])
@pytest.mark.parametrize("field", ["review", "delivery"])
@pytest.mark.parametrize("malformed_body", [None, "x" * 16_385])
def test_provider_review_and_delivery_bodies_are_bounded_strings(
    tmp_path: Path,
    provider: str,
    field: str,
    malformed_body: str | None,
) -> None:
    """A missing or unbounded provider body must never mint provider success."""
    module = load_module(f"koios_ci_malformed_{provider}_{field}_{malformed_body is None}")
    snapshot = provider_snapshot()
    login = "coderabbitai[bot]" if provider == "coderabbit" else "chatgpt-codex-connector[bot]"
    collection = (
        snapshot["reviews"]
        if field == "review"
        else [
            *snapshot["issue_comments"],
            *snapshot["review_comments"],
        ]
    )
    row = next(item for item in collection if item["user"]["login"] == login)
    row["body"] = malformed_body

    result = make_finalizer(module, tmp_path, FakeAPI(snapshot=snapshot)).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    expected = "provider-evidence-malformed" if malformed_body is None else "provider-evidence-unbounded"
    assert expected in blocker_codes(result)


def test_malformed_provider_timestamp_cannot_override_newer_finding(
    tmp_path: Path,
) -> None:
    """Lexical timestamp tricks must not make an old PASS look newest."""
    module = load_module("koios_ci_provider_timestamp_ordering")
    snapshot = provider_snapshot()
    old_pass = next(item for item in snapshot["reviews"] if item["user"]["login"] == "coderabbitai[bot]")
    old_pass["submitted_at"] = "zzzz"
    newer_finding = copy.deepcopy(old_pass)
    newer_finding.update(
        {
            "id": 999,
            "submitted_at": "2026-07-27T12:00:00Z",
            "body": "blocking finding on current head",
        }
    )
    snapshot["reviews"].append(newer_finding)
    api = FakeAPI(snapshot=snapshot)

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-malformed" in blocker_codes(result)
    assert api.live_labels == set()


def test_rest_only_incomplete_thread_readback_is_an_explicit_blocker(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_rest_threads")
    snapshot = provider_snapshot()
    snapshot["readback"] = "rest-does-not-prove-thread-resolution"
    api = FakeAPI(snapshot=snapshot)
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-readback-incomplete" in blocker_codes(result)


def test_unverified_hosted_provider_contract_cannot_mint_success(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_provider_contract")
    api = FakeAPI()
    finalizer = make_finalizer(
        module,
        tmp_path,
        api,
        provider_contract_verified=False,
    )
    result = finalizer.finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-contract-unverified" in blocker_codes(result)
    assert api.labels == []


def test_codex_native_evidence_stays_disabled_without_a_hosted_canary(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_codex_hosted_canary")

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(),
        codex_hosted_canary_verified=False,
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "codex-hosted-canary-unverified" in blocker_codes(result)
    assert result["labels"] == {"ci-final": "pending", "ai-review-ready": "pending"}


def test_codex_requires_explicit_current_review_pass_and_newer_app_delivery(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_codex_explicit_pass")
    for mutation in ("non-pass", "older-delivery"):
        snapshot = provider_snapshot()
        codex_review = next(
            item for item in snapshot["reviews"] if item["user"]["login"] == "chatgpt-codex-connector[bot]"
        )
        codex_delivery = next(
            item for item in snapshot["review_comments"] if item["user"]["login"] == "chatgpt-codex-connector[bot]"
        )
        if mutation == "non-pass":
            codex_review["body"] = "Provider-native review completed"
        else:
            codex_delivery["updated_at"] = "2026-07-27T09:00:00Z"

        result = make_finalizer(
            module,
            tmp_path / mutation,
            FakeAPI(snapshot=snapshot),
        ).finalize(REPOSITORY, 42)

        assert result["complete"] is False
        assert "codex-evidence-invalid" in blocker_codes(result)


@pytest.mark.parametrize(
    "prefix",
    ("", "Immutable platform final subject / "),
)
def test_gate_jobs_use_reusable_workflow_api_names_and_optional_caller_prefix(
    prefix: str,
) -> None:
    module = load_module(f"koios_ci_gate_names_{bool(prefix)}")
    state = {"gates": {}}
    rows = [
        {"name": f"{prefix}{name}", "status": "completed", "conclusion": "success"}
        for name in (
            "Platform / deterministic final evidence",
            "Platform / security evidence",
            "Platform / coverage evidence verification",
        )
    ]

    assert module._evaluate_gate_jobs(state, rows, module.FinalizerConfig(None).gate_jobs) == []
    assert state["gates"] == {
        "deterministic": "passed",
        "security": "passed",
        "coverage": "passed",
    }


def test_unimplemented_label_invalidation_controller_blocks_promotion(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_invalidation_controller")
    api = FakeAPI()
    finalizer = make_finalizer(
        module,
        tmp_path,
        api,
        invalidation_controller_verified=False,
    )

    result = finalizer.finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "label-invalidation-controller-unverified" in blocker_codes(result)
    assert api.labels == []


def test_provider_polling_stops_at_the_bounded_timeout(tmp_path: Path) -> None:
    module = load_module("koios_ci_provider_timeout")
    snapshot = provider_snapshot()
    snapshot["reviews"] = []
    snapshot["issue_comments"] = []
    snapshot["review_comments"] = []
    api = FakeAPI(snapshot=snapshot)
    clock = [0.0]

    def monotonic() -> float:
        return clock[0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    config = module.FinalizerConfig(
        workflow=module.WorkflowIdentity(
            workflow_id=WORKFLOW_ID,
            path=WORKFLOW_PATH,
            sha=PLATFORM_SHA,
            event="workflow_dispatch",
            source_path=SOURCE_PATH,
            promoter=PROMOTER,
        ),
        controller=module.ControllerIdentity(
            path=CONTROLLER_WORKFLOW_PATH,
            event="workflow_dispatch",
            repository=REPOSITORY,
            repository_id=123,
            run_id=CONTROLLER_RUN_ID,
            run_attempt=1,
            sha=CONTROLLER_SHA,
            ref="refs/heads/main",
        ),
        subject_run_id=SUBJECT_RUN_ID,
        subject_run_attempt=1,
        provider_contract_verified=True,
        invalidation_controller_verified=True,
        latest_run_inventory_verified=True,
        external_singleflight_verified=True,
        codex_hosted_canary_verified=True,
    )
    finalizer = module.Finalizer(
        api=api,
        state_dir=tmp_path,
        config=config,
        monotonic=monotonic,
        sleep=sleep,
    )

    result = finalizer.finalize(
        REPOSITORY,
        42,
        timeout_seconds=3,
        poll_seconds=1,
    )

    assert result["complete"] is False
    assert "provider-timeout" in blocker_codes(result)
    assert clock[0] == 3
    assert api.provider_reads == 4


def test_dependabot_ai_bypass_remains_disabled_without_native_provenance(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_dependabot")
    dependabot = {
        "login": "dependabot[bot]",
        "id": 49699333,
        "type": "Bot",
    }
    api = FakeAPI(pulls=[pull(author=dependabot)])
    api.snapshot = module.ProviderUnavailable("outage")
    blocked = make_finalizer(module, tmp_path / "blocked", api).finalize(
        REPOSITORY,
        42,
    )

    assert blocked["complete"] is False
    assert blocked["dependabot"]["proof"] == "disabled"
    assert "dependabot-bypass-disabled" in blocker_codes(blocked)


def test_rerun_targets_only_revalidated_exact_attempt_once(tmp_path: Path) -> None:
    module = load_module("koios_ci_rerun")
    failed = run(conclusion="failure")
    api = FakeAPI(runs=[failed], jobs_payload=jobs(conclusion="failure"))
    finalizer = make_finalizer(module, tmp_path, api)

    first = finalizer.finalize(REPOSITORY, 42, rerun_failed=True)

    assert "automatic-rerun-not-exact-attempt-safe" in blocker_codes(first)
    assert api.reruns == []
    assert api.labels == []


def test_dry_run_plans_labels_but_performs_no_write(tmp_path: Path) -> None:
    module = load_module("koios_ci_dry_run")
    api = FakeAPI()
    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
        dry_run=True,
    )

    assert result["complete"] is False
    assert result["labels"]["ci-final"] == "planned"
    assert result["labels"]["ai-review-ready"] == "planned"
    assert "dry-run-no-mutations" in blocker_codes(result)
    assert api.labels == []
    assert list(tmp_path.glob("*.json")) == []


def test_state_and_schema_are_closed(tmp_path: Path) -> None:
    module = load_module("koios_ci_schema")
    result = make_finalizer(module, tmp_path, FakeAPI()).finalize(
        REPOSITORY,
        42,
    )
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(result)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["key"]["additionalProperties"] is False
    assert set(result) == set(schema["required"])
    with pytest.raises(ValueError, match="unexpected state fields"):
        module.validate_state({**result, "attacker": "accepted"})


def test_schema_rejects_internally_inconsistent_complete_state(
    tmp_path: Path,
) -> None:
    """Removing schema success invariants must admit this forged completion."""
    module = load_module("koios_ci_schema_complete_invariants")
    result = make_finalizer(module, tmp_path, FakeAPI()).finalize(
        REPOSITORY,
        42,
    )
    result["gates"]["security"] = "failed"
    result["blockers"] = [
        {
            "code": "security-gate-failed",
            "detail": "security failed",
        }
    ]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(result)


def test_cli_exposes_only_requested_commands_and_json_status() -> None:
    module = load_module("koios_ci_cli")
    parser = module.build_parser()

    finalize = parser.parse_args(["finalize", "--repo", REPOSITORY, "--pr", "42", "--dry-run"])
    resume = parser.parse_args(["resume", "--repo", REPOSITORY, "--pr", "42", "--head", HEAD])
    status = parser.parse_args(["status", "--repo", REPOSITORY, "--pr", "42", "--head", HEAD, "--json"])

    assert finalize.command == "finalize"
    assert resume.command == "resume"
    assert status.command == "status"
    assert status.json is True
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "finalize",
                "--repo",
                REPOSITORY,
                "--pr",
                "42",
                "--token",
                "github_pat_forbidden",
            ]
        )


@pytest.mark.parametrize(
    "token",
    (
        "ghp_personal",
        "github_pat_fine_grained",
        "gho_oauth",
        "ghu_user_to_server",
        "",
    ),
)
def test_rest_adapter_rejects_non_installation_tokens(token: str) -> None:
    module = load_module(f"koios_ci_token_{len(token)}_{token[:3]}")

    with pytest.raises(ValueError, match="installation token"):
        module.GitHubRestAPI(token)


def test_rest_adapter_pins_current_platform_api_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The platform contract uses GitHub's current 2026-03-10 API version."""
    module = load_module("koios_ci_rest_api_version")
    captured_headers: dict[str, str] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit > 0
            return b"{}"

    def fake_urlopen(request: Any, *, timeout: int) -> Response:
        assert timeout == 20
        captured_headers.update({name.lower(): value for name, value in request.header_items()})
        return Response()

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    api = module.GitHubRestAPI("ghs_ephemeral_test_only")

    api._request("GET", "/zen")

    assert captured_headers["x-github-api-version"] == "2026-03-10"


def test_rest_adapter_completely_paginates_review_threads_and_nested_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("koios_ci_rest_provider_boundary")
    api = module.GitHubRestAPI("ghs_ephemeral_test_only")
    monkeypatch.setattr(api, "_paginate", lambda *args, **kwargs: [])
    observed: list[dict[str, Any]] = []

    def graphql(_query: str, variables: dict[str, Any]) -> dict[str, Any]:
        observed.append(dict(variables))
        if variables.get("threadId") == "THREAD-1":
            assert variables["commentsCursor"] == "COMMENTS-1"
            return {
                "node": {
                    "comments": {
                        "nodes": [{"author": {"login": "chatgpt-codex-connector[bot]"}}],
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    }
                }
            }
        if variables.get("threadsCursor") == "THREADS-1":
            return {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "THREAD-2",
                                    "isResolved": True,
                                    "comments": {
                                        "nodes": [],
                                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                                    },
                                }
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        assert variables["threadsCursor"] is None
        return {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "THREAD-1",
                                "isResolved": False,
                                "comments": {
                                    "nodes": [{"author": {"login": "coderabbitai[bot]"}}],
                                    "pageInfo": {
                                        "hasNextPage": True,
                                        "endCursor": "COMMENTS-1",
                                    },
                                },
                            }
                        ],
                        "pageInfo": {"hasNextPage": True, "endCursor": "THREADS-1"},
                    }
                }
            }
        }

    monkeypatch.setattr(api, "_graphql", graphql, raising=False)

    snapshot = api.provider_snapshot(REPOSITORY, 42, HEAD)

    assert snapshot["readback"] == "complete"
    assert snapshot["threads"] == {
        "nodes": [
            {
                "isResolved": False,
                "comments": {
                    "nodes": [
                        {"author": {"login": "coderabbitai[bot]"}},
                        {"author": {"login": "chatgpt-codex-connector[bot]"}},
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                },
            },
            {
                "isResolved": True,
                "comments": {
                    "nodes": [],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                },
            },
        ],
        "pageInfo": {"hasNextPage": False, "endCursor": None},
    }
    assert len(observed) == 3


def test_rest_adapter_builds_closed_source_attestation_from_trusted_run_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("koios_ci_rest_source_boundary")
    api = module.GitHubRestAPI("ghs_ephemeral_test_only")
    controller = controller_run()
    subject = run()
    monkeypatch.setattr(api, "get_repository", lambda _repository: FakeAPI().repository)
    monkeypatch.setattr(api, "get_pull", lambda _repository, _number: pull())
    monkeypatch.setattr(
        api,
        "get_workflow_run",
        lambda _repository, run_id: controller if run_id == CONTROLLER_RUN_ID else subject,
    )

    attestation_result = api.get_run_source_attestation(
        REPOSITORY,
        42,
        HEAD,
        BASE,
        CONTROLLER_RUN_ID,
        1,
        SUBJECT_RUN_ID,
        1,
    )

    assert attestation_result == {
        "readback": "complete",
        "schema_version": "koios-run-source-v3",
        "repository_id": 123,
        "pull_request": 42,
        "pr_head_sha": HEAD,
        "base_sha": BASE,
        "controller_run_id": CONTROLLER_RUN_ID,
        "controller_run_attempt": 1,
        "controller_workflow_id": CONTROLLER_WORKFLOW_ID,
        "controller_path": CONTROLLER_WORKFLOW_PATH,
        "controller_sha": CONTROLLER_SHA,
        "controller_ref": "refs/heads/main",
        "controller_event": "workflow_dispatch",
        "subject_run_id": SUBJECT_RUN_ID,
        "subject_run_attempt": 1,
        "subject_workflow_id": WORKFLOW_ID,
        "subject_path": WORKFLOW_PATH,
        "subject_sha": CONTROLLER_SHA,
        "authored_source_selector": SOURCE_PATH,
        "resolved_source_sha": PLATFORM_SHA,
        "source_path": SOURCE_PATH,
        "source_sha": PLATFORM_SHA,
        "promoter": PROMOTER,
    }


def test_rest_adapter_inventory_preserves_every_same_head_run_attempt_and_zero_job_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("koios_ci_rest_run_inventory")
    api = module.GitHubRestAPI("ghs_ephemeral_test_only")
    selected = run()
    failed = run(
        run_id=SUBJECT_RUN_ID + 1,
        conclusion="startup_failure",
        created_at="2026-07-27T10:05:00Z",
    )
    monkeypatch.setattr(api, "get_repository", lambda _repository: FakeAPI().repository)
    monkeypatch.setattr(api, "_paginate", lambda *args, **kwargs: [selected, failed])
    monkeypatch.setattr(
        api,
        "list_run_jobs",
        lambda _repository, run_id, attempt: {
            "run_id": run_id,
            "run_attempt": attempt,
            "total_count": 0 if run_id == failed["id"] else 3,
            "jobs": [] if run_id == failed["id"] else jobs(run_id=run_id, attempt=attempt)["jobs"],
        },
    )

    inventory = api.list_same_head_run_inventory(
        REPOSITORY,
        42,
        HEAD,
        BASE,
        WORKFLOW_ID,
        SUBJECT_RUN_ID,
        1,
        PLATFORM_SHA,
    )

    assert inventory["readback"] == "complete"
    assert [(item["id"], item["attempt"], item["conclusion"], item["total_jobs"]) for item in inventory["runs"]] == [
        (SUBJECT_RUN_ID, 1, "success", 3),
        (SUBJECT_RUN_ID + 1, 1, "startup_failure", 0),
    ]


def test_cli_finalize_and_json_status_use_injected_api_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("koios_ci_cli_execution")
    environment: dict[str, str] = {
        "KOIOS_FINAL_WORKFLOW_ID": str(WORKFLOW_ID),
        "KOIOS_FINAL_WORKFLOW_PATH": WORKFLOW_PATH,
        "KOIOS_PLATFORM_SHA": PLATFORM_SHA,
        "KOIOS_FINAL_WORKFLOW_EVENT": "workflow_dispatch",
        "KOIOS_FINAL_SOURCE_PATH": SOURCE_PATH,
        "KOIOS_FINAL_PROMOTER_LOGIN": PROMOTER["login"],
        "KOIOS_FINAL_PROMOTER_ID": str(PROMOTER["id"]),
        "KOIOS_FINAL_PROMOTER_TYPE": PROMOTER["type"],
        "KOIOS_SUBJECT_RUN_ID": str(SUBJECT_RUN_ID),
        "KOIOS_SUBJECT_RUN_ATTEMPT": "1",
        "KOIOS_PROVIDER_CONTRACT_VERIFIED": "1",
        "KOIOS_INVALIDATION_CONTROLLER_VERIFIED": "1",
        "KOIOS_LATEST_RUN_INVENTORY_VERIFIED": "1",
        "KOIOS_EXTERNAL_SINGLEFLIGHT_VERIFIED": "1",
        "KOIOS_CODEX_HOSTED_CANARY_VERIFIED": "1",
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": "123",
        "GITHUB_RUN_ID": str(CONTROLLER_RUN_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": CONTROLLER_SHA,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": (f"{REPOSITORY}/{CONTROLLER_WORKFLOW_PATH}@refs/heads/main"),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    api = FakeAPI()
    finalize_output = io.StringIO()

    finalize_code = module.main(
        [
            "--state-dir",
            str(tmp_path),
            "finalize",
            "--repo",
            REPOSITORY,
            "--pr",
            "42",
        ],
        api=api,
        stdout=finalize_output,
    )
    status_output = io.StringIO()
    status_code = module.main(
        [
            "--state-dir",
            str(tmp_path / "new-process"),
            "status",
            "--repo",
            REPOSITORY,
            "--pr",
            "42",
            "--head",
            HEAD,
            "--json",
        ],
        api=api,
        stdout=status_output,
    )

    assert finalize_code == 0
    assert status_code == 0
    assert json.loads(finalize_output.getvalue())["complete"] is True
    assert json.loads(status_output.getvalue())["complete"] is True
    assert api.labels == [
        (REPOSITORY, 42, ("ci-final", "ai-review-ready")),
    ]


def test_environment_binds_the_current_trusted_controller_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropping any current-run binding must fail closed configuration."""
    module = load_module("koios_ci_current_run_environment")
    environment: dict[str, str] = {
        "KOIOS_FINAL_WORKFLOW_ID": str(WORKFLOW_ID),
        "KOIOS_FINAL_WORKFLOW_PATH": WORKFLOW_PATH,
        "KOIOS_PLATFORM_SHA": PLATFORM_SHA,
        "KOIOS_FINAL_WORKFLOW_EVENT": "workflow_dispatch",
        "KOIOS_FINAL_SOURCE_PATH": SOURCE_PATH,
        "KOIOS_FINAL_PROMOTER_LOGIN": PROMOTER["login"],
        "KOIOS_FINAL_PROMOTER_ID": str(PROMOTER["id"]),
        "KOIOS_FINAL_PROMOTER_TYPE": PROMOTER["type"],
        "KOIOS_SUBJECT_RUN_ID": str(SUBJECT_RUN_ID),
        "KOIOS_SUBJECT_RUN_ATTEMPT": "1",
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": "123",
        "GITHUB_RUN_ID": str(CONTROLLER_RUN_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": CONTROLLER_SHA,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": (f"{REPOSITORY}/{CONTROLLER_WORKFLOW_PATH}@refs/heads/main"),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    config = module.config_from_environment()
    controller = config.controller
    assert controller is not None
    actual = {
        name: getattr(controller, name, None)
        for name in (
            "path",
            "repository",
            "repository_id",
            "run_id",
            "run_attempt",
            "sha",
            "ref",
        )
    }
    assert actual == {
        "path": CONTROLLER_WORKFLOW_PATH,
        "repository": REPOSITORY,
        "repository_id": 123,
        "run_id": CONTROLLER_RUN_ID,
        "run_attempt": 1,
        "sha": CONTROLLER_SHA,
        "ref": "refs/heads/main",
    }
    assert config.subject_run_id == SUBJECT_RUN_ID
    assert config.subject_run_attempt == 1


def test_real_run_shape_without_workflow_sha_uses_referenced_workflow_and_attestation(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_real_run")
    payload = run()
    assert "workflow_sha" not in payload

    result = make_finalizer(module, tmp_path, FakeAPI(runs=[payload])).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is True


def test_missing_trusted_source_attestation_blocks_before_labels(tmp_path: Path) -> None:
    module = load_module("koios_ci_source_unavailable")
    api = FakeAPI()
    api.source_attestation = {"readback": "unsupported"}

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert "source-provenance-unavailable" in blocker_codes(result)
    assert api.labels == []


def test_user_dispatched_run_is_not_promoter_bound(tmp_path: Path) -> None:
    module = load_module("koios_ci_user_dispatch")
    malicious = {
        **run(),
        "actor": {"login": "attacker", "id": 99, "type": "User"},
        "triggering_actor": {"login": "attacker", "id": 99, "type": "User"},
    }
    api = FakeAPI(runs=[malicious])

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert "wrong-workflow-promoter" in blocker_codes(result)
    assert api.labels == []


def test_live_label_readback_makes_new_state_dir_idempotent(tmp_path: Path) -> None:
    module = load_module("koios_ci_cross_process")
    api = FakeAPI()

    first = make_finalizer(module, tmp_path / "process-1", api).finalize(
        REPOSITORY,
        42,
    )
    second = make_finalizer(module, tmp_path / "process-2", api).resume(
        REPOSITORY,
        42,
        HEAD,
    )

    assert first["complete"] is True
    assert second["complete"] is True
    assert api.labels == [
        (REPOSITORY, 42, ("ci-final", "ai-review-ready")),
    ]


def test_status_reconstructs_live_authority_without_local_state(tmp_path: Path) -> None:
    module = load_module("koios_ci_status_cross_process")
    api = FakeAPI()
    make_finalizer(module, tmp_path / "process-1", api).finalize(REPOSITORY, 42)

    status = make_finalizer(module, tmp_path / "process-2", api).status(
        REPOSITORY,
        42,
        HEAD,
    )

    assert status["complete"] is True
    assert status["dry_run"] is True
    assert api.labels == [
        (REPOSITORY, 42, ("ci-final", "ai-review-ready")),
    ]


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("drop", "label-write-not-confirmed"),
        ("partial", "label-write-not-confirmed"),
    ),
)
def test_label_write_requires_exact_live_readback(
    tmp_path: Path,
    mode: str,
    expected: str,
) -> None:
    module = load_module(f"koios_ci_label_{mode}")
    api = FakeAPI()
    api.label_mode = mode

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert expected in blocker_codes(result)
    assert result["complete"] is False


def test_ambiguous_label_timeout_reconciles_from_live_state(tmp_path: Path) -> None:
    module = load_module("koios_ci_label_timeout")
    api = FakeAPI()
    api.label_mode = "timeout-after-write"
    api.label_error = module.AmbiguousMutation("label request timed out")

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is True
    assert api.live_labels == {"ci-final", "ai-review-ready"}


def test_ambiguous_label_timeout_without_write_stays_blocked(tmp_path: Path) -> None:
    module = load_module("koios_ci_label_timeout_dropped")
    api = FakeAPI()
    api.label_mode = "drop"
    api.label_error = module.AmbiguousMutation("label request timed out")

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "label-write-not-confirmed" in blocker_codes(result)
    assert api.live_labels == set()


def test_rejected_label_write_rolls_back_both_final_labels(tmp_path: Path) -> None:
    module = load_module("koios_ci_label_rejected")
    api = FakeAPI()
    api.label_error = module.GitHubAPIError("write rejected after uncertain response")

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "label-write-rejected" in blocker_codes(result)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_unexpected_exception_after_label_write_rolls_back_live_labels(
    tmp_path: Path,
) -> None:
    """An adapter exception after a successful write is an ambiguous mutation."""
    module = load_module("koios_ci_unexpected_label_write_exception")
    api = FakeAPI()
    api.label_error = ValueError("adapter projection failed after write")

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "label-write-exception" in blocker_codes(result)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_read_only_status_never_rolls_back_live_labels(tmp_path: Path) -> None:
    module = load_module("koios_ci_read_only_labels")
    api = FakeAPI(snapshot=module.ProviderUnavailable("outage"))
    api.live_labels.update({"ci-final", "ai-review-ready"})

    result = make_finalizer(module, tmp_path, api).status(
        REPOSITORY,
        42,
        HEAD,
    )

    assert result["complete"] is False
    assert "provider-outage" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_partial_ai_label_is_rolled_back_when_full_write_is_not_confirmed(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_label_partial_ai")
    api = FakeAPI()
    api.label_mode = "partial-ai"

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "label-write-not-confirmed" in blocker_codes(result)
    assert "ai-review-ready" not in api.live_labels
    assert api.removed_labels == ["ai-review-ready"]


def test_post_write_head_drift_refuses_rollback_mutation(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_label_rollback")
    api = FakeAPI(
        pulls=[
            pull(),
            pull(),
            pull(),
            pull(head_sha=NEW_HEAD),
            pull(head_sha=NEW_HEAD),
        ]
    )

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert "pull-head-changed" in blocker_codes(result)
    assert "label-rollback-unconfirmed" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_new_attempt_starting_after_gate_evaluation_blocks_label_promotion(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_attempt_toctou")
    api = FakeAPI()
    api.advance_run_after_jobs = run(
        attempt=2,
        conclusion="startup_failure",
        created_at="2026-07-27T10:05:00Z",
    )

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "wrong-subject-run-attempt" in blocker_codes(result)
    assert api.labels == []


def test_head_change_after_provider_readback_cannot_mint_completion(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_provider_toctou")
    api = FakeAPI()
    api.advance_head_after_provider = True

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "pull-head-changed" in blocker_codes(result)
    assert "label-rollback-unconfirmed" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_final_boundary_outage_after_provider_pass_rolls_back_labels(
    tmp_path: Path,
) -> None:
    """A transient final repository read failure must not strand promoted labels."""
    module = load_module("koios_ci_final_boundary_outage")

    class FinalBoundaryOutageAPI(FakeAPI):
        fail_next_repository_read = False

        def get_repository(self, repository: str) -> dict[str, Any]:
            if self.fail_next_repository_read:
                self.fail_next_repository_read = False
                raise module.ProviderUnavailable("outage")
            return super().get_repository(repository)

        def provider_snapshot(
            self,
            repository: str,
            number: int,
            head_sha: str,
        ) -> dict[str, Any]:
            snapshot = super().provider_snapshot(repository, number, head_sha)
            self.fail_next_repository_read = True
            return snapshot

    api = FinalBoundaryOutageAPI()
    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "final-provenance-readback-unavailable" in blocker_codes(result)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_labels_are_reread_before_completion(tmp_path: Path) -> None:
    """Removing final label readback must mint a false complete state."""
    module = load_module("koios_ci_final_label_readback")
    api = FakeAPI()
    api.remove_labels_after_provider = True

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "final-labels-missing" in blocker_codes(result)


def test_head_change_while_provider_is_pending_refuses_rollback_mutation(
    tmp_path: Path,
) -> None:
    """A polling boundary change must not leave stale final labels."""
    module = load_module("koios_ci_poll_boundary_rollback")
    snapshot = provider_snapshot()
    snapshot["reviews"] = [item for item in snapshot["reviews"] if item["user"]["login"] != "coderabbitai[bot]"]
    snapshot["issue_comments"] = []
    api = FakeAPI(snapshot=snapshot)
    api.advance_head_after_provider = True

    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
        timeout_seconds=2,
        poll_seconds=1,
    )

    assert result["complete"] is False
    assert "pull-head-changed" in blocker_codes(result)
    assert "label-rollback-unconfirmed" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_dependabot_full_rest_shape_still_does_not_enable_bypass(
    tmp_path: Path,
) -> None:
    module = load_module("koios_ci_dependabot_full_shape")
    actor = {
        "login": "dependabot[bot]",
        "id": 49699333,
        "type": "Bot",
        "avatar_url": "https://avatars.example/dependabot",
        "site_admin": False,
    }
    api = FakeAPI(pulls=[pull(author=actor)])

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert result["dependabot"]["proof"] == "disabled"
    assert "dependabot-bypass-disabled" in blocker_codes(result)


def test_controller_and_subject_run_identities_are_distinct_types() -> None:
    """Collapsing the executing controller into its completed subject must fail."""
    module = load_module("koios_ci_distinct_run_types")

    assert hasattr(module, "ControllerIdentity")
    assert "controller_run" in module.TOP_LEVEL_STATE_FIELDS
    assert "subject_run" in module.TOP_LEVEL_STATE_FIELDS
    assert "run" not in module.TOP_LEVEL_STATE_FIELDS


def test_controller_and_subject_run_ids_cannot_alias() -> None:
    """Reusing the executing run as its own completed subject must fail closed."""
    module = load_module("koios_ci_run_alias")

    with pytest.raises(ValueError, match="must be distinct"):
        module.FinalizerConfig(
            workflow=module.WorkflowIdentity(
                workflow_id=WORKFLOW_ID,
                path=WORKFLOW_PATH,
                sha=PLATFORM_SHA,
                event="workflow_dispatch",
                source_path=SOURCE_PATH,
                promoter=PROMOTER,
            ),
            controller=module.ControllerIdentity(
                path=CONTROLLER_WORKFLOW_PATH,
                event="workflow_dispatch",
                repository=REPOSITORY,
                repository_id=123,
                run_id=SUBJECT_RUN_ID,
                run_attempt=1,
                sha=CONTROLLER_SHA,
                ref="refs/heads/main",
            ),
            subject_run_id=SUBJECT_RUN_ID,
            subject_run_attempt=1,
        )


def test_closed_top_level_review_thread_connection_can_pass(tmp_path: Path) -> None:
    """Treating a closed GraphQL connection as a bare list must fail this test."""
    module = load_module("koios_ci_closed_thread_connection")
    snapshot = provider_snapshot()
    snapshot["threads"] = {
        "nodes": [],
        "pageInfo": {
            "hasNextPage": False,
            "endCursor": None,
        },
    }

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(snapshot=snapshot),
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is True


def test_top_level_review_thread_pagination_blocks_completion(
    tmp_path: Path,
) -> None:
    """Ignoring reviewThreads.pageInfo can hide unresolved provider findings."""
    module = load_module("koios_ci_paginated_thread_connection")
    snapshot = provider_snapshot()
    snapshot["threads"] = {
        "nodes": [],
        "pageInfo": {
            "hasNextPage": True,
            "endCursor": "hidden-next-page",
        },
    }

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(snapshot=snapshot),
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-readback-incomplete" in blocker_codes(result)


def test_top_level_review_thread_connection_rejects_extra_fields(
    tmp_path: Path,
) -> None:
    """Ignoring a second pagination channel can hide an incomplete readback."""
    module = load_module("koios_ci_extra_thread_pagination")
    snapshot = provider_snapshot()
    snapshot["threads_page_info"] = {
        "hasNextPage": True,
        "endCursor": "hidden-next-page",
    }

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(snapshot=snapshot),
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-malformed" in blocker_codes(result)


def test_review_thread_comment_pagination_blocks_completion(
    tmp_path: Path,
) -> None:
    """A truncated comment connection must not hide the provider author."""
    module = load_module("koios_ci_thread_comment_pagination")
    snapshot = provider_snapshot(unresolved=True)
    snapshot["threads"]["nodes"][0]["comments"]["pageInfo"] = {
        "hasNextPage": True,
        "endCursor": "hidden-comment-page",
    }

    result = make_finalizer(
        module,
        tmp_path,
        FakeAPI(snapshot=snapshot),
    ).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "provider-evidence-readback-incomplete" in blocker_codes(result)


def test_provider_api_error_after_label_write_rolls_back_both_labels(
    tmp_path: Path,
) -> None:
    """Letting a known API exception unwind leaves stale final labels live."""
    module = load_module("koios_ci_provider_api_error_rollback")
    api = FakeAPI(snapshot=module.GitHubAPIError("malformed provider payload"))

    try:
        result = make_finalizer(module, tmp_path, api).finalize(
            REPOSITORY,
            42,
        )
    except module.GitHubAPIError:
        pytest.fail("post-mutation API errors must be reconciled, not raised")

    assert result["complete"] is False
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_unexpected_provider_adapter_exception_rolls_back_both_labels(
    tmp_path: Path,
) -> None:
    """Trusted-adapter parser exceptions must enter the same rollback path."""
    module = load_module("koios_ci_provider_adapter_exception")
    api = FakeAPI(snapshot=ValueError("malformed adapter projection"))

    result = make_finalizer(module, tmp_path, api).finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert "finalizer-execution-failed" in blocker_codes(result)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_resume_hard_blocker_rolls_back_labels_from_pending_attempt(
    tmp_path: Path,
) -> None:
    """A later same-head provenance failure cannot retain pending-review labels."""
    module = load_module("koios_ci_resume_hard_blocker_rollback")
    snapshot = provider_snapshot()
    snapshot["reviews"] = [item for item in snapshot["reviews"] if item["user"]["login"] != "coderabbitai[bot]"]
    snapshot["issue_comments"] = []
    api = FakeAPI(snapshot=snapshot)
    finalizer = make_finalizer(module, tmp_path, api)

    pending = finalizer.finalize(REPOSITORY, 42, timeout_seconds=0)
    assert pending["phase"] == "awaiting-providers"
    assert api.live_labels == {"ci-final", "ai-review-ready"}

    api.runs.append(run(attempt=2, conclusion="startup_failure"))
    blocked = finalizer.resume(REPOSITORY, 42, HEAD)

    assert blocked["complete"] is False
    assert "wrong-subject-run-attempt" in blocker_codes(blocked)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_rollback_refuses_repository_identity_drift(tmp_path: Path) -> None:
    """Rollback must not remove labels from a repository recreated at the path."""
    module = load_module("koios_ci_rollback_repository_drift")

    class RepositoryDriftAPI(FakeAPI):
        def provider_snapshot(
            self,
            repository: str,
            number: int,
            head_sha: str,
        ) -> dict[str, Any]:
            self.repository = {
                **self.repository,
                "id": 999,
            }
            raise module.ProviderUnavailable("outage")

    api = RepositoryDriftAPI()
    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "label-rollback-unconfirmed" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


def test_boolean_subject_attempt_from_api_cannot_reach_label_mutation(
    tmp_path: Path,
) -> None:
    """Python bool/int equality must not satisfy an exact run attempt."""
    module = load_module("koios_ci_boolean_subject_attempt")
    api = FakeAPI(runs=[run(attempt=True)])

    try:
        result = make_finalizer(module, tmp_path, api).finalize(
            REPOSITORY,
            42,
        )
    except ValueError:
        pytest.fail("malformed run identity must become a pre-mutation blocker")

    assert result["complete"] is False
    assert "wrong-subject-run-attempt" in blocker_codes(result)
    assert api.labels == []
    assert api.live_labels == set()


def test_boolean_attestation_attempt_cannot_satisfy_exact_binding(
    tmp_path: Path,
) -> None:
    """JSON boolean values must not compare equal to integer attempt ids."""
    module = load_module("koios_ci_boolean_attestation_attempt")
    api = FakeAPI()
    api.source_attestation["subject_run_attempt"] = True

    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "source-provenance-invalid" in blocker_codes(result)
    assert api.labels == []


def test_malformed_base_readback_after_label_write_is_reconciled(
    tmp_path: Path,
) -> None:
    """Malformed API provenance must not unwind past post-write reconciliation."""
    module = load_module("koios_ci_malformed_base_after_write")
    api = FakeAPI(
        pulls=[
            pull(),
            pull(),
            pull(),
            pull(base_sha="not-a-commit-sha"),
        ]
    )

    try:
        result = make_finalizer(module, tmp_path, api).finalize(
            REPOSITORY,
            42,
        )
    except ValueError:
        pytest.fail("malformed post-write provenance must become a blocker")

    assert result["complete"] is False
    assert "pull-payload-invalid" in blocker_codes(result)
    assert "label-rollback-unconfirmed" in blocker_codes(result)
    assert api.live_labels == {"ci-final", "ai-review-ready"}
    assert api.removed_labels == []


@pytest.mark.parametrize("field", ("workflow", "controller_run", "subject_run"))
def test_complete_state_requires_non_null_identity_in_code_and_schema(
    tmp_path: Path,
    field: str,
) -> None:
    """Code and schema must reject the same forged complete state."""
    module = load_module("koios_ci_complete_workflow_required")
    state = make_finalizer(module, tmp_path, FakeAPI()).finalize(
        REPOSITORY,
        42,
    )
    state[field] = None

    with pytest.raises(ValueError, match="complete state"):
        module.validate_state(state)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(state)


def test_state_run_paths_are_validated_as_normalized_workflows(
    tmp_path: Path,
) -> None:
    """Code validation must enforce the same run-path shape as the schema."""
    module = load_module("koios_ci_state_run_path")
    state = make_finalizer(module, tmp_path, FakeAPI()).finalize(
        REPOSITORY,
        42,
    )
    state["controller_run"]["path"] = "../../attacker.yml@main"

    with pytest.raises(ValueError, match="controller run identity"):
        module.validate_state(state)


def test_state_schema_rejects_traversal_inside_a_run_ref(
    tmp_path: Path,
) -> None:
    """Schema readers must reject the same non-normalized ref as code."""
    module = load_module("koios_ci_state_schema_run_ref")
    state = make_finalizer(module, tmp_path, FakeAPI()).finalize(
        REPOSITORY,
        42,
    )
    state["controller_run"]["path"] = f"{CONTROLLER_WORKFLOW_PATH}@refs/heads/../main"

    with pytest.raises(ValueError, match="controller run identity"):
        module.validate_state(state)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(state)


def test_workflow_source_path_rejects_traversal_and_encoded_separators() -> None:
    """An immutable source must name one direct workflow YAML file."""
    module = load_module("koios_ci_source_path_normalization")

    for suffix in (
        "../../attacker.yml",
        "%2e%2e%2fattacker.yml",
        r"..\attacker.yml",
    ):
        with pytest.raises(ValueError, match="source path"):
            module.WorkflowIdentity(
                workflow_id=WORKFLOW_ID,
                path=WORKFLOW_PATH,
                sha=PLATFORM_SHA,
                event="workflow_dispatch",
                source_path=(f"koios-ai/ci-platform/.github/workflows/{suffix}@{PLATFORM_SHA}"),
                promoter=PROMOTER,
            )


def test_oversized_state_is_rejected_before_atomic_replacement(
    tmp_path: Path,
) -> None:
    """A state larger than the load limit must not replace readable state."""
    module = load_module("koios_ci_state_write_limit")
    finalizer = make_finalizer(module, tmp_path, FakeAPI())
    state = finalizer.finalize(REPOSITORY, 42)
    path = finalizer._path(REPOSITORY, 42, HEAD)
    original = path.read_bytes()
    state["complete"] = False
    state["phase"] = "blocked"
    state["blockers"] = [
        {
            "code": "oversized",
            "detail": "x" * (1024 * 1024),
        }
    ]

    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        finalizer._save(state)

    assert path.read_bytes() == original


def test_oversized_provider_string_is_rejected_before_evaluation(
    tmp_path: Path,
) -> None:
    """External payload strings must be bounded before scanning or logging."""
    module = load_module("koios_ci_provider_string_limit")
    snapshot = provider_snapshot()
    snapshot["reviews"][0]["body"] = "x" * 20_000
    api = FakeAPI(snapshot=snapshot)

    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "provider-evidence-unbounded" in blocker_codes(result)
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}


def test_oversized_provider_error_reason_is_not_persisted(
    tmp_path: Path,
) -> None:
    """Provider exception text is external input and must not reach state."""
    module = load_module("koios_ci_provider_error_limit")

    class OversizedReasonAPI(FakeAPI):
        def provider_snapshot(
            self,
            repository: str,
            number: int,
            head_sha: str,
        ) -> dict[str, Any]:
            raise module.ProviderUnavailable("x" * 20_000)

    api = OversizedReasonAPI()
    result = make_finalizer(module, tmp_path, api).finalize(
        REPOSITORY,
        42,
    )

    assert result["complete"] is False
    assert "provider-unavailable" in blocker_codes(result)
    assert all(len(item["detail"]) <= 512 and "x" * 512 not in item["detail"] for item in result["blockers"])
    assert api.live_labels == set()


def test_oversized_repository_input_is_rejected_before_api_use() -> None:
    """Repository input must have a closed length as well as a character set."""
    module = load_module("koios_ci_repository_length")

    with pytest.raises(ValueError, match="repository"):
        module._validate_command_inputs(
            f"{'a' * 300}/repo",
            1,
            0,
            1,
        )


def test_boolean_pull_request_number_is_rejected_before_api_use() -> None:
    """JSON booleans must never satisfy an integer command boundary."""
    module = load_module("koios_ci_boolean_pull_number")

    with pytest.raises(ValueError, match="pull request number"):
        module._validate_command_inputs(
            REPOSITORY,
            True,
            0,
            1,
        )


def test_stale_writer_cannot_replace_newer_exact_head_state(
    tmp_path: Path,
) -> None:
    """Two writers that observed the same prior bytes need compare-and-swap."""
    module = load_module("koios_ci_state_compare_and_swap")
    first_api = FakeAPI()
    second_api = FakeAPI()
    first = make_finalizer(module, tmp_path, first_api)
    second = make_finalizer(module, tmp_path, second_api)
    repository_payload = first_api.get_repository(REPOSITORY)
    pull_payload = first_api.get_pull(REPOSITORY, 42)
    first_state = first._initial_state(
        REPOSITORY,
        42,
        repository_payload,
        pull_payload,
        dry_run=False,
    )
    second_state = second._initial_state(
        REPOSITORY,
        42,
        repository_payload,
        pull_payload,
        dry_run=False,
    )

    first._save(first_state)
    destination = first._path(REPOSITORY, 42, HEAD)
    authoritative = destination.read_bytes()

    with pytest.raises(module.StateConflictError, match="changed"):
        second._save(second_state)

    assert destination.read_bytes() == authoritative
    assert list(tmp_path.glob("*.tmp")) == []


def test_concurrent_exact_head_writers_have_one_cas_winner(
    tmp_path: Path,
) -> None:
    """Two simultaneous stale writers must never both report durable success."""
    module = load_module("koios_ci_state_concurrent_compare_and_swap")
    first_api = FakeAPI()
    second_api = FakeAPI()
    first = make_finalizer(module, tmp_path, first_api)
    second = make_finalizer(module, tmp_path, second_api)
    repository_payload = first_api.get_repository(REPOSITORY)
    pull_payload = first_api.get_pull(REPOSITORY, 42)
    first_state = first._initial_state(
        REPOSITORY,
        42,
        repository_payload,
        pull_payload,
        dry_run=False,
    )
    second_state = second._initial_state(
        REPOSITORY,
        42,
        repository_payload,
        pull_payload,
        dry_run=False,
    )
    barrier = Barrier(2)

    def save(finalizer: Any, state: dict[str, Any]) -> str:
        barrier.wait()
        try:
            finalizer._save(state)
        except module.StateConflictError:
            return "conflict"
        return "saved"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result()
            for future in (
                pool.submit(save, first, first_state),
                pool.submit(save, second, second_state),
            )
        ]

    destination = first._path(REPOSITORY, 42, HEAD)
    assert sorted(outcomes) == ["conflict", "saved"]
    module.validate_state(json.loads(destination.read_text(encoding="utf-8")))
    assert list(tmp_path.glob("*.lock")) == []
    assert list(tmp_path.glob(f".{destination.name}.*.tmp")) == []


def test_existing_writer_lock_is_not_removed_or_clobbered(
    tmp_path: Path,
) -> None:
    """A writer that does not own the lock must leave it and state untouched."""
    module = load_module("koios_ci_state_lock_collision")
    api = FakeAPI()
    finalizer = make_finalizer(module, tmp_path, api)
    state = finalizer._initial_state(
        REPOSITORY,
        42,
        api.get_repository(REPOSITORY),
        api.get_pull(REPOSITORY, 42),
        dry_run=False,
    )
    destination = finalizer._path(REPOSITORY, 42, HEAD)
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock = destination.with_suffix(".json.lock")
    lock.write_text("other-writer", encoding="utf-8")

    with pytest.raises(module.StateConflictError, match="writer lock"):
        finalizer._save(state)

    assert lock.read_text(encoding="utf-8") == "other-writer"
    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_preexisting_legacy_temporary_file_is_not_clobbered(
    tmp_path: Path,
) -> None:
    """Atomic writes must use an exclusive unique same-directory temporary."""
    module = load_module("koios_ci_unique_state_temporary")
    api = FakeAPI()
    finalizer = make_finalizer(module, tmp_path, api)
    state = finalizer._initial_state(
        REPOSITORY,
        42,
        api.get_repository(REPOSITORY),
        api.get_pull(REPOSITORY, 42),
        dry_run=False,
    )
    destination = finalizer._path(REPOSITORY, 42, HEAD)
    destination.parent.mkdir(parents=True, exist_ok=True)
    legacy_temporary = destination.with_suffix(".json.tmp")
    legacy_temporary.write_bytes(b"another-writer")

    finalizer._save(state)

    assert destination.exists()
    assert legacy_temporary.read_bytes() == b"another-writer"
    assert list(tmp_path.glob(f".{destination.name}.*.tmp")) == []


def test_state_conflict_after_label_promotion_rolls_back_and_blocks(
    tmp_path: Path,
) -> None:
    """A non-durable PASS must revoke final labels and fail closed."""
    module = load_module("koios_ci_persistence_conflict_rollback")

    class LockBeforeCompletionAPI(FakeAPI):
        lock_path: Path | None = None

        def provider_snapshot(
            self,
            repository: str,
            number: int,
            head_sha: str,
        ) -> dict[str, Any]:
            assert self.lock_path is not None
            self.lock_path.write_text("other-writer", encoding="utf-8")
            return super().provider_snapshot(repository, number, head_sha)

    api = LockBeforeCompletionAPI()
    finalizer = make_finalizer(module, tmp_path, api)
    destination = finalizer._path(REPOSITORY, 42, HEAD)
    api.lock_path = destination.with_suffix(".json.lock")

    result = finalizer.finalize(REPOSITORY, 42)

    assert result["complete"] is False
    assert result["phase"] == "blocked"
    assert "state-write-conflict" in blocker_codes(result)
    assert result["labels"] == {
        "ci-final": "pending",
        "ai-review-ready": "pending",
    }
    assert api.live_labels == set()
    assert set(api.removed_labels) == {"ci-final", "ai-review-ready"}
    assert api.lock_path.read_text(encoding="utf-8") == "other-writer"
    assert not destination.exists()
