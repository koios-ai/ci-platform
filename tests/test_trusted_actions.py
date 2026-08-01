from __future__ import annotations

import hashlib
import importlib.util
import json
import urllib.error
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = ROOT / ".github" / "actions"
SHA = "a" * 40
BASE_SHA = "b" * 40
PLATFORM_SHA = "c" * 40


def load_module(relative: str, name: str) -> ModuleType:
    path = ACTIONS / relative
    assert path.is_file(), f"missing action implementation: {path.relative_to(ROOT)}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_action(relative: str) -> dict[str, Any]:
    path = ACTIONS / relative / "action.yml"
    assert path.is_file(), f"missing action descriptor: {path.relative_to(ROOT)}"
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_trusted_actions_have_closed_composite_boundaries() -> None:
    expected_inputs = {
        "invalidate-final-labels": {
            "pull_request_number",
            "event_head_sha",
            "lifecycle_event",
            "trusted_source_sha",
        },
        "dispatch-finalizer": {
            "subject_run_id",
            "subject_run_attempt",
            "subject_workflow_id",
            "subject_workflow_path",
            "finalizer_workflow_path",
            "default_branch",
        },
        "final-preflight": {
            "pull_request_number",
            "event_head_sha",
            "event_base_sha",
            "required_fast_context",
            "required_fast_workflow_id",
        },
        "verify-evidence": {"expected_head_sha", "expected_evidence_digest"},
        "publish-final-contexts": {
            "pull_request_number",
            "expected_head_sha",
            "evidence_digest",
            "upstream_result",
            "gate_passed",
            "coverage_upload_result",
        },
        "promote-ai-review": {
            "pull_request_number",
            "expected_head_sha",
            "security_conclusion",
            "coverage_conclusion",
        },
        "publish-ai-context": {
            "pull_request_number",
            "expected_head_sha",
            "evaluation_result",
            "expected_evidence_digest",
        },
    }
    for name, inputs in expected_inputs.items():
        action = load_action(name)
        assert set(action["inputs"]) == inputs
        assert action["runs"]["using"] == "composite"
        serialized = json.dumps(action)
        assert "secrets." not in serialized
        for step in action["runs"]["steps"]:
            assert "${{ inputs." not in str(step.get("run", ""))


def test_preflight_accepts_only_current_same_repository_candidate() -> None:
    module = load_module("final-preflight/preflight.py", "final_preflight")
    pull: dict[str, Any] = {
        "state": "open",
        "draft": False,
        "head": {
            "sha": SHA,
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "labels": [{"name": "ci-final"}],
    }

    module.validate_pull_request(
        pull,
        repository="koios-ai/example",
        event_head_sha=SHA,
        event_base_sha=BASE_SHA,
    )
    for field, value in (
        ("state", "closed"),
        ("draft", True),
        ("head.sha", BASE_SHA),
        ("head.repo.full_name", "attacker/fork"),
        ("base.sha", SHA),
        ("base.ref", "release"),
        ("base.repo.full_name", "attacker/fork"),
        ("base.repo.id", 456),
        ("labels", []),
    ):
        candidate = json.loads(json.dumps(pull))
        target: Any = candidate
        parts = field.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        with pytest.raises(ValueError):
            module.validate_pull_request(
                candidate,
                repository="koios-ai/example",
                event_head_sha=SHA,
                event_base_sha=BASE_SHA,
            )


def test_preflight_recomputes_profile_and_canonical_digest() -> None:
    module = load_module("final-preflight/preflight.py", "final_preflight_digest")
    paths = ["README.md", "src/features/current_form.py", "tests/test_form.py"]
    assert module.classify_profile(paths) == "critical-ml"
    assert module.classify_profile(["README.md"]) == "baseline"
    assert module.classify_profile(["src/widget.py"]) == "python"
    assert module.classify_profile([".coderabbit.yaml"]) == "critical-ml"
    expected = hashlib.sha256(b"README.md\nsrc/features/current_form.py\ntests/test_form.py\n").hexdigest()
    assert module.canonical_changed_files_digest(reversed(paths)) == expected


def test_preflight_requires_successful_github_actions_check_on_current_head() -> None:
    module = load_module("final-preflight/preflight.py", "final_preflight_check")
    check = {
        "id": 456,
        "name": "CI / required",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 15368, "slug": "github-actions"},
        "details_url": "https://github.com/koios-ai/example/actions/runs/123",
    }
    call = {
        "run_id": 123,
        "run_attempt": 1,
        "repository": "koios-ai/example",
        "server_url": "https://github.com",
        "token": "redacted",
        "api_url": "https://api.github.com",
    }
    selected = module.select_required_check([check], "CI / required", SHA, **call)
    assert selected == check
    for field, value in (
        ("name", "CI / almost-required"),
        ("head_sha", BASE_SHA),
        ("status", "in_progress"),
        ("conclusion", "neutral"),
        ("app.slug", "third-party"),
        ("details_url", "https://example.invalid/result"),
    ):
        candidate = json.loads(json.dumps(check))
        target: Any = candidate
        parts = field.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        with pytest.raises(ValueError):
            module.select_required_check([candidate], "CI / required", SHA, **call)


def _write_json(path: Path, value: Any) -> str:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_evidence_verifier_rejects_tampering_and_wrong_platform(tmp_path: Path) -> None:
    module = load_module("verify-evidence/verify_evidence.py", "verify_evidence")
    components = {
        "changed-files.json": b'["src/example.py"]\n',
        "coverage.xml": b"<coverage/>\n",
        "coverage.json": b'{"totals":{"percent_covered":100}}\n',
        "coverage-summary.json": b'{"status":"passed"}\n',
        "typing-summary.json": b'{"status":"passed"}\n',
        "documentation-summary.json": b'{"status":"passed"}\n',
        "environment-summary.json": b'{"status":"passed"}\n',
        "critical-safety-summary.json": b'{"status":"not-applicable"}\n',
        "smoke-summary.json": b'{"status":"passed"}\n',
        "test-policy-summary.json": b'{"status":"passed"}\n',
        "pytest-junit.xml": (b'<testsuites tests="1" errors="0" failures="0" skipped="0"/>\n'),
        "repository-pre-hooks-summary.json": b'{"status":"passed"}\n',
        "repository-post-hooks-summary.json": b'{"status":"passed"}\n',
        "policy-non-regression-summary.json": b'{"status":"passed"}\n',
    }
    for name, content in components.items():
        (tmp_path / name).write_bytes(content)
    manifest = {
        "base_sha": BASE_SHA,
        "changed_files_digest": hashlib.sha256(b"src/example.py\n").hexdigest(),
        "head_sha": SHA,
        "platform_sha": PLATFORM_SHA,
        "profile": "python",
        "quality_debt_digest": "e" * 64,
        "security_evidence_digest": "f" * 64,
        "coverage_sha256": hashlib.sha256(components["coverage.xml"]).hexdigest(),
        "changed_files_evidence_digest": hashlib.sha256(components["changed-files.json"]).hexdigest(),
        "coverage_json_digest": hashlib.sha256(components["coverage.json"]).hexdigest(),
        "coverage_summary_digest": hashlib.sha256(components["coverage-summary.json"]).hexdigest(),
        "typing_summary_digest": hashlib.sha256(components["typing-summary.json"]).hexdigest(),
        "documentation_summary_digest": hashlib.sha256(components["documentation-summary.json"]).hexdigest(),
        "environment_summary_digest": hashlib.sha256(components["environment-summary.json"]).hexdigest(),
        "critical_safety_summary_digest": hashlib.sha256(components["critical-safety-summary.json"]).hexdigest(),
        "smoke_summary_digest": hashlib.sha256(components["smoke-summary.json"]).hexdigest(),
        "test_policy_summary_digest": hashlib.sha256(components["test-policy-summary.json"]).hexdigest(),
        "pytest_junit_digest": hashlib.sha256(components["pytest-junit.xml"]).hexdigest(),
        "repository_pre_hooks_digest": hashlib.sha256(components["repository-pre-hooks-summary.json"]).hexdigest(),
        "repository_post_hooks_digest": hashlib.sha256(components["repository-post-hooks-summary.json"]).hexdigest(),
        "policy_non_regression_digest": hashlib.sha256(components["policy-non-regression-summary.json"]).hexdigest(),
    }
    digest = _write_json(tmp_path / "evidence-manifest.json", manifest)

    assert module.verify_evidence(tmp_path, SHA, digest, PLATFORM_SHA)["head_sha"] == SHA
    (tmp_path / "coverage.xml").write_text("<tampered/>\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        module.verify_evidence(tmp_path, SHA, digest, PLATFORM_SHA)
    with pytest.raises(ValueError, match="platform"):
        module.verify_evidence(tmp_path, SHA, digest, "d" * 40)

    (tmp_path / "unexpected-coverage.xml").write_text(
        "<coverage/>\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exact file allowlist"):
        module.verify_evidence(tmp_path, SHA, digest, PLATFORM_SHA)
    (tmp_path / "unexpected-coverage.xml").unlink()

    (tmp_path / "coverage.xml").write_bytes(components["coverage.xml"])
    (tmp_path / "pytest-junit.xml").write_text(
        '<testsuites tests="1" errors="0" failures="0" skipped="1"/>\n',
        encoding="utf-8",
    )
    manifest["pytest_junit_digest"] = hashlib.sha256((tmp_path / "pytest-junit.xml").read_bytes()).hexdigest()
    skipped_digest = _write_json(tmp_path / "evidence-manifest.json", manifest)
    with pytest.raises(ValueError, match="fully green"):
        module.verify_evidence(tmp_path, SHA, skipped_digest, PLATFORM_SHA)

    (tmp_path / "pytest-junit.xml").write_text(
        '<!DOCTYPE testsuites [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<testsuites tests="0" errors="0" failures="0" skipped="0"/>\n',
        encoding="utf-8",
    )
    manifest["pytest_junit_digest"] = hashlib.sha256((tmp_path / "pytest-junit.xml").read_bytes()).hexdigest()
    unsafe_xml_digest = _write_json(tmp_path / "evidence-manifest.json", manifest)
    with pytest.raises(ValueError, match="unsafe XML"):
        module.verify_evidence(tmp_path, SHA, unsafe_xml_digest, PLATFORM_SHA)


def test_final_context_publisher_payload_is_exact_and_provenance_bound() -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publish_final_contexts",
    )
    pull: dict[str, Any] = {
        "state": "open",
        "draft": False,
        "head": {
            "sha": SHA,
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "labels": [{"name": "ci-final"}],
    }
    module.validate_candidate(pull, "koios-ai/example", SHA)
    context = module.resolve_context(
        ".github/workflows/final-required.yml",
        "publish-security",
    )
    assert context == "Security / required"
    with pytest.raises(ValueError):
        module.resolve_context(
            ".github/workflows/coderabbit-final.yml",
            "publish-coderabbit",
        )

    identity = {
        "repository": "koios-ai/example",
        "repository_id": "123",
        "pull_request_number": "42",
        "head_sha": SHA,
        "context": context,
        "workflow_ref": ("koios-ai/example/.github/workflows/final-required.yml@refs/heads/main"),
        "workflow_sha": BASE_SHA,
        "run_id": "456",
        "run_attempt": "2",
        "evidence_digest": "d" * 64,
        "deepsource_evidence_digest": "e" * 64,
        "action_ref": PLATFORM_SHA,
        "job_id": "publish-security",
        "job_check_run_id": "789",
    }
    payload = module.build_check_payload(identity, "success")
    assert payload["name"] == "Security / required"
    assert payload["head_sha"] == SHA
    assert payload["conclusion"] == "success"
    assert payload["details_url"] == ("https://github.com/koios-ai/example/actions/runs/456/attempts/2")
    assert payload["external_id"].startswith("ci-platform-final:v1:")
    for field in identity:
        changed = dict(identity)
        changed[field] = f"{identity[field]}x"
        assert module.canonical_external_id(changed) != module.canonical_external_id(identity)

    assert (
        module.derive_conclusion(
            "Security / required",
            upstream_result="success",
            gate_passed="true",
            coverage_upload_result="not-applicable",
            evidence_digest="d" * 64,
        )
        == "success"
    )
    assert (
        module.derive_conclusion(
            "Coverage / required",
            upstream_result="failure",
            gate_passed="",
            coverage_upload_result="skipped",
            evidence_digest="",
        )
        == "failure"
    )
    assert (
        module.derive_conclusion(
            "Coverage / required",
            upstream_result="cancelled",
            gate_passed="",
            coverage_upload_result="cancelled",
            evidence_digest="",
        )
        == "cancelled"
    )

    for changed in (
        {**pull, "state": "closed"},
        {**pull, "draft": True},
        {**pull, "labels": []},
        {**pull, "base": {**pull["base"], "ref": "release"}},
        {**pull, "head": {"sha": BASE_SHA, "repo": {"full_name": "koios-ai/example"}}},
        {**pull, "head": {"sha": SHA, "repo": {"full_name": "attacker/fork"}}},
    ):
        with pytest.raises(ValueError):
            module.validate_candidate(changed, "koios-ai/example", SHA)


def test_label_invalidator_is_current_head_bound_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "invalidate-final-labels/invalidate_final_labels.py",
        "invalidate_final_labels",
    )
    pull: dict[str, Any] = {
        "state": "open",
        "head": {"sha": SHA},
        "labels": [
            {"name": "ci-final"},
            {"name": "ai-review-ready"},
            {"name": "keep-me"},
        ],
    }
    assert module.labels_to_remove(pull, SHA) == [
        "ai-review-ready",
        "ci-final",
    ]
    assert module.labels_to_remove({**pull, "head": {"sha": BASE_SHA}}, SHA) == []
    assert module.labels_to_remove({**pull, "state": "closed"}, SHA) == []
    assert module.trusted_action_source("koios-ai/ci-platform", PLATFORM_SHA, "", "")
    assert module.trusted_action_source("", "", BASE_SHA, BASE_SHA)
    assert not module.trusted_action_source("", "", BASE_SHA, SHA)

    class RedirectedResponse:
        def __enter__(self) -> RedirectedResponse:
            return self

        def __exit__(self, *args: Any) -> None:
            del args

        def geturl(self) -> str:
            return "https://attacker.invalid/redirect"

        def read(self) -> bytes:
            return b"{}"

    class RedirectedOpener:
        def open(self, request: Any, timeout: int) -> RedirectedResponse:
            del request, timeout
            return RedirectedResponse()

    monkeypatch.setattr(module, "_opener", lambda: RedirectedOpener())
    with pytest.raises(RuntimeError, match="redirect"):
        module.api_request(
            "GET",
            "/repos/koios-ai/example/pulls/42",
            token="redacted",
        )


@pytest.mark.parametrize(
    ("event", "draft"),
    [("synchronize", False), ("reopened", False), ("converted_to_draft", True)],
)
def test_label_invalidator_binds_the_exact_lifecycle_transition(
    event: str,
    draft: bool,
) -> None:
    module = load_module(
        "invalidate-final-labels/invalidate_final_labels.py",
        f"invalidate_final_labels_lifecycle_{event}",
    )
    pull = {
        "state": "open",
        "draft": draft,
        "head": {"sha": SHA},
        "labels": [{"name": "ci-final"}],
    }

    assert module.current_final_labels(pull, SHA, event) == {"ci-final"}
    with pytest.raises(ValueError, match="lifecycle"):
        module.current_final_labels(pull, SHA, "ready_for_review")
    if event == "converted_to_draft":
        with pytest.raises(ValueError, match="draft"):
            module.current_final_labels({**pull, "draft": False}, SHA, event)


@pytest.mark.parametrize("existing_status", [None, "queued", "bogus"])
def test_exact_subject_attempt_dispatch_is_idempotent_with_rigorous_readback(
    monkeypatch: pytest.MonkeyPatch,
    existing_status: str | None,
) -> None:
    module = load_module(
        "dispatch-finalizer/dispatch_finalizer.py",
        "dispatch_finalizer_exact_attempt",
    )
    actor = {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
    subject = {
        "id": 500,
        "run_attempt": 2,
        "workflow_id": 700,
        "path": ".github/workflows/final-subject-v1.yml",
        "head_branch": "main",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "display_title": (f"koios-final-subject-v1|repo=123|pr=42|head={SHA}|base={BASE_SHA}|platform={PLATFORM_SHA}"),
        "head_sha": BASE_SHA,
        "actor": actor,
        "triggering_actor": actor,
    }
    repository = {"id": 123, "full_name": "koios-ai/example", "default_branch": "main"}
    pull = {
        "number": 42,
        "state": "open",
        "draft": False,
        "head": {"sha": SHA, "repo": {"id": 123, "full_name": "koios-ai/example"}},
        "base": {"sha": BASE_SHA, "repo": {"id": 123, "full_name": "koios-ai/example"}},
    }
    dispatched = existing_status is not None
    posts: list[dict[str, Any]] = []

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        expect_empty: bool = False,
    ) -> Any:
        nonlocal dispatched
        del token, expect_empty
        if path == "/repos/koios-ai/example":
            return repository
        if path == "/repos/koios-ai/example/pulls/42":
            return pull
        if path == "/repos/koios-ai/example/actions/runs/500/attempts/2":
            return subject
        if path.endswith("/runs?event=workflow_dispatch&per_page=100"):
            rows = []
            if dispatched:
                rows.append(
                    {
                        "id": 900,
                        "run_attempt": 1,
                        "workflow_id": 800,
                        "display_title": (
                            f"koios-finalizer-v1|repo=123|pr=42|head={SHA}|base={BASE_SHA}|subject=500|attempt=2"
                        ),
                        "event": "workflow_dispatch",
                        "head_branch": "main",
                        "head_sha": BASE_SHA,
                        "actor": actor,
                        "triggering_actor": actor,
                        "status": existing_status or "queued",
                        "conclusion": None,
                    }
                )
            return {"total_count": len(rows), "workflow_runs": rows}
        if path.endswith("/dispatches") and method == "POST":
            assert payload is not None
            posts.append(payload)
            dispatched = True
            return None
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module, "api_request", fake_api_request)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    arguments = (
        "koios-ai/example",
        500,
        2,
        700,
        ".github/workflows/final-subject-v1.yml",
        ".github/workflows/finalize-python-v1.yml",
        "main",
    )
    if existing_status == "bogus":
        with pytest.raises(RuntimeError, match="controller readback is malformed"):
            module.dispatch_finalizer(*arguments, platform_sha=PLATFORM_SHA, token="redacted")
        assert posts == []
        return

    run_id = module.dispatch_finalizer(*arguments, platform_sha=PLATFORM_SHA, token="redacted")

    assert run_id == 900
    expected_post = {
        "ref": "main",
        "inputs": {
            "pull_request_number": "42",
            "head_sha": SHA,
            "base_sha": BASE_SHA,
            "subject_run_id": "500",
            "subject_run_attempt": "2",
            "subject_workflow_id": "700",
            "subject_workflow_path": ".github/workflows/final-subject-v1.yml",
        },
    }
    assert posts == ([] if existing_status else [expected_post])
    assert not module.trusted_dispatch_caller(
        "koios-ai/example/.github/workflows/final-subject-v1.yml@refs/heads/main",
        "koios-ai/example",
        "main",
        event_name="workflow_dispatch",
        actor="github-actions[bot]",
        triggering_actor="github-actions[bot]",
        current_run_id=500,
        current_run_attempt=2,
        subject_run_id=500,
        subject_run_attempt=2,
    )
    assert module.trusted_dispatch_caller(
        "koios-ai/example/.github/workflows/resume-finalizer-v1.yml@refs/heads/main",
        "koios-ai/example",
        "main",
        event_name="workflow_run",
        actor="github-actions[bot]",
        triggering_actor="github-actions[bot]",
        current_run_id=600,
        current_run_attempt=1,
        subject_run_id=500,
        subject_run_attempt=2,
    )
    for current_attempt, runtime_actor, runtime_triggering_actor in (
        (2, "github-actions[bot]", "github-actions[bot]"),
        (1, "octocat", "github-actions[bot]"),
        (1, "github-actions[bot]", "octocat"),
    ):
        assert not module.trusted_dispatch_caller(
            "koios-ai/example/.github/workflows/resume-finalizer-v1.yml@refs/heads/main",
            "koios-ai/example",
            "main",
            event_name="workflow_run",
            actor=runtime_actor,
            triggering_actor=runtime_triggering_actor,
            current_run_id=600,
            current_run_attempt=current_attempt,
            subject_run_id=500,
            subject_run_attempt=2,
        )
    assert not module.trusted_dispatch_caller(
        "koios-ai/example/.github/workflows/attacker.yml@refs/heads/main",
        "koios-ai/example",
        "main",
        event_name="workflow_run",
        actor="github-actions[bot]",
        triggering_actor="github-actions[bot]",
        current_run_id=600,
        current_run_attempt=1,
        subject_run_id=500,
        subject_run_attempt=2,
    )
    expected_title = f"koios-finalizer-v1|repo=123|pr=42|head={SHA}|base={BASE_SHA}|subject=500|attempt=2"
    trusted_controller = {
        "display_title": expected_title,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": BASE_SHA,
        "actor": actor,
        "triggering_actor": actor,
    }
    assert module.trusted_controller_identity(trusted_controller, expected_title, "main", BASE_SHA)
    assert not module.trusted_controller_identity(
        {**trusted_controller, "head_sha": SHA},
        expected_title,
        "main",
        BASE_SHA,
    )
    assert not module.trusted_controller_identity(
        {**trusted_controller, "actor": {"login": "octocat", "id": 1, "type": "User"}},
        expected_title,
        "main",
        BASE_SHA,
    )


@pytest.mark.parametrize("first_failure", ["timeout", "http-500"])
def test_label_invalidator_reconciles_first_delete_failure_and_removes_both(
    monkeypatch: pytest.MonkeyPatch,
    first_failure: str,
) -> None:
    module = load_module(
        "invalidate-final-labels/invalidate_final_labels.py",
        f"invalidate_final_labels_{first_failure}",
    )
    present = {"ai-review-ready", "ci-final", "keep-me"}
    delete_attempts: list[str] = []
    readbacks = 0
    sleeps: list[int] = []

    def pull() -> dict[str, Any]:
        return {
            "state": "open",
            "head": {"sha": SHA},
            "labels": [{"name": label} for label in sorted(present)],
        }

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        expect_empty: bool = False,
    ) -> Any:
        nonlocal readbacks
        del token, expect_empty
        if method == "GET":
            readbacks += 1
            return pull()
        label = path.rsplit("/", 1)[1]
        delete_attempts.append(label)
        if label == "ai-review-ready" and delete_attempts.count(label) == 1:
            if first_failure == "timeout":
                raise RuntimeError("transport failure")
            raise module.ApiError(method, path, 500)
        present.discard(label)
        return None

    monkeypatch.setattr(module, "api_request", fake_api_request)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)

    changed = module.invalidate_final_labels(
        "koios-ai/example",
        42,
        SHA,
        pull(),
        token="redacted",
    )

    assert changed is True
    assert delete_attempts == [
        "ai-review-ready",
        "ci-final",
        "ai-review-ready",
    ]
    assert readbacks == 2
    assert sleeps == [1]
    assert present == {"keep-me"}


def test_label_invalidator_aggregates_only_after_bounded_exact_head_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "invalidate-final-labels/invalidate_final_labels.py",
        "invalidate_final_labels_persistent_failure",
    )
    present = {"ai-review-ready", "ci-final"}
    delete_attempts: list[str] = []
    readbacks = 0

    def pull() -> dict[str, Any]:
        return {
            "state": "open",
            "head": {"sha": SHA},
            "labels": [{"name": label} for label in sorted(present)],
        }

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        expect_empty: bool = False,
    ) -> Any:
        nonlocal readbacks
        del token, expect_empty
        if method == "GET":
            readbacks += 1
            return pull()
        label = path.rsplit("/", 1)[1]
        delete_attempts.append(label)
        if label == "ai-review-ready":
            raise module.ApiError(method, path, 503)
        present.discard(label)
        return None

    monkeypatch.setattr(module, "api_request", fake_api_request)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    with pytest.raises(RuntimeError, match="remaining=ai-review-ready"):
        module.invalidate_final_labels(
            "koios-ai/example",
            42,
            SHA,
            pull(),
            token="redacted",
        )

    assert delete_attempts == [
        "ai-review-ready",
        "ci-final",
        "ai-review-ready",
        "ai-review-ready",
    ]
    assert readbacks == module.MAX_INVALIDATION_ATTEMPTS
    assert present == {"ai-review-ready"}


def test_label_invalidator_confirms_absence_when_no_final_label_was_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "invalidate-final-labels/invalidate_final_labels.py",
        "invalidate_final_labels_absent",
    )
    pull = {
        "state": "open",
        "head": {"sha": SHA},
        "labels": [{"name": "keep-me"}],
    }
    calls: list[tuple[str, str]] = []

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        expect_empty: bool = False,
    ) -> Any:
        del token, expect_empty
        calls.append((method, path))
        assert method == "GET"
        return pull

    monkeypatch.setattr(module, "api_request", fake_api_request)

    assert (
        module.invalidate_final_labels(
            "koios-ai/example",
            42,
            SHA,
            pull,
            token="redacted",
        )
        is False
    )
    assert calls == [("GET", "/repos/koios-ai/example/pulls/42")]


def test_ai_review_promoter_requires_current_head_and_both_owned_final_checks() -> None:
    module = load_module(
        "promote-ai-review/promote_ai_review.py",
        "promote_ai_review",
    )
    pull: dict[str, Any] = {
        "number": 42,
        "state": "open",
        "draft": False,
        "head": {
            "sha": SHA,
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "labels": [{"name": "ci-final"}],
    }
    module.validate_candidate(
        pull,
        repository="koios-ai/example",
        head_sha=SHA,
        require_ready=False,
    )
    checks: list[dict[str, Any]] = []
    for context, suffix in (
        ("Security / required", "security-required"),
        ("Coverage / required", "coverage-required"),
    ):
        checks.append(
            {
                "id": len(checks) + 1,
                "name": context,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
                "details_url": ("https://github.com/koios-ai/example/actions/runs/456/attempts/2"),
                "external_id": f"ci-platform-final:v1:{'d' * 64}:{suffix}",
                "app": {"id": 15368, "slug": "github-actions"},
                "output": {"summary": (f"Workflow SHA: `{BASE_SHA}`. Platform SHA: `{PLATFORM_SHA}`.")},
            }
        )
    selected = module.select_successful_final_checks(
        checks,
        repository="koios-ai/example",
        head_sha=SHA,
        run_id=456,
        run_attempt=2,
        workflow_sha=BASE_SHA,
        action_ref=PLATFORM_SHA,
    )
    assert {item["name"] for item in selected} == {
        "Security / required",
        "Coverage / required",
    }

    for field, value in (
        ("conclusion", "failure"),
        ("head_sha", BASE_SHA),
        ("app.slug", "attacker"),
        ("details_url", "https://attacker.invalid/result"),
    ):
        candidate = json.loads(json.dumps(checks))
        target: Any = candidate[0]
        parts = field.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        with pytest.raises(ValueError):
            module.select_successful_final_checks(
                candidate,
                repository="koios-ai/example",
                head_sha=SHA,
                run_id=456,
                run_attempt=2,
                workflow_sha=BASE_SHA,
                action_ref=PLATFORM_SHA,
            )

    with pytest.raises(ValueError):
        module.validate_candidate(
            {
                **pull,
                "labels": [
                    {"name": "ci-final"},
                    {"name": "ai-review-ready"},
                ],
            },
            repository="koios-ai/example",
            head_sha=SHA,
            require_ready=False,
        )
    with pytest.raises(ValueError, match="protected default branch"):
        module.validate_candidate(
            {
                **pull,
                "base": {**pull["base"], "ref": "release"},
            },
            repository="koios-ai/example",
            head_sha=SHA,
            require_ready=False,
        )


def _promoter_checks() -> list[dict[str, Any]]:
    return [
        {
            "id": index,
            "name": context,
            "head_sha": SHA,
            "status": "completed",
            "conclusion": "success",
            "details_url": ("https://github.com/koios-ai/example/actions/runs/456/attempts/2"),
            "external_id": f"ci-platform-final:v1:{'d' * 64}:{suffix}",
            "app": {"id": 15368, "slug": "github-actions"},
            "output": {"summary": (f"Workflow SHA: `{BASE_SHA}`. Platform SHA: `{PLATFORM_SHA}`.")},
        }
        for index, (context, suffix) in enumerate(
            (
                ("Security / required", "security-required"),
                ("Coverage / required", "coverage-required"),
            ),
            start=1,
        )
    ]


def _set_promoter_environment(
    monkeypatch: pytest.MonkeyPatch,
    output_path: Path,
) -> None:
    values = {
        "GH_TOKEN": "redacted",
        "GITHUB_REPOSITORY": "koios-ai/example",
        "GITHUB_OUTPUT": str(output_path),
        "INPUT_PULL_REQUEST_NUMBER": "42",
        "INPUT_EXPECTED_HEAD_SHA": SHA,
        "INPUT_SECURITY_CONCLUSION": "success",
        "INPUT_COVERAGE_CONCLUSION": "success",
        "ACTION_REF": PLATFORM_SHA,
        "ACTION_REPOSITORY": "koios-ai/ci-platform",
        "RUNTIME_API_URL": "https://api.github.com",
        "RUNTIME_SERVER_URL": "https://github.com",
        "RUNTIME_EVENT_NAME": "pull_request_target",
        "RUNTIME_JOB_ID": "promote-ai-review",
        "RUNTIME_RUN_ID": "456",
        "RUNTIME_RUN_ATTEMPT": "2",
        "RUNTIME_REPOSITORY_ID": "123",
        "RUNTIME_WORKFLOW_REF": ("koios-ai/example/.github/workflows/final-required.yml@refs/heads/main"),
        "RUNTIME_WORKFLOW_SHA": BASE_SHA,
        "RUNTIME_WORKFLOW_REPOSITORY": "koios-ai/example",
        "RUNTIME_WORKFLOW_FILE_PATH": ".github/workflows/final-required.yml",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_ai_review_promoter_rechecks_newest_attempt_around_label_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_module(
        "promote-ai-review/promote_ai_review.py",
        "promote_ai_review_success",
    )
    output_path = tmp_path / "github-output"
    _set_promoter_environment(monkeypatch, output_path)
    pull = _live_prt_pull()
    run = _live_prt_run()
    newest_checks: list[int] = []

    def newest(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        newest_checks.append(len(newest_checks) + 1)

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        ambiguous_write: bool = False,
    ) -> Any:
        del token, ambiguous_write
        if path.endswith("/pulls/42"):
            return json.loads(json.dumps(pull))
        if path.endswith("/actions/runs/456"):
            return json.loads(json.dumps(run))
        if path.endswith("/issues/42/labels") and method == "POST":
            assert payload == {"labels": ["ai-review-ready"]}
            pull["labels"].append({"name": "ai-review-ready"})
            return pull["labels"]
        raise AssertionError((method, path))

    monkeypatch.setattr(module, "api_request", fake_api_request)
    monkeypatch.setattr(
        module,
        "paginated_check_runs",
        lambda repository, head_sha, *, token: _promoter_checks(),
    )
    monkeypatch.setattr(module.CORE, "assert_newest_prt_attempt", newest)

    module.main()

    assert newest_checks == [1, 2]
    assert {"name": "ai-review-ready"} in pull["labels"]
    assert output_path.read_text(encoding="utf-8") == "promoted=true\n"


def test_ai_review_promoter_rolls_back_when_post_write_run_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_module(
        "promote-ai-review/promote_ai_review.py",
        "promote_ai_review_rollback",
    )
    output_path = tmp_path / "github-output"
    _set_promoter_environment(monkeypatch, output_path)
    pull = _live_prt_pull()
    run = _live_prt_run()
    newest_checks: list[int] = []
    label_written = False

    def newest(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        newest_checks.append(len(newest_checks) + 1)

    def fake_api_request(
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        ambiguous_write: bool = False,
    ) -> Any:
        nonlocal label_written
        del token, ambiguous_write
        if path.endswith("/pulls/42"):
            return json.loads(json.dumps(pull))
        if path.endswith("/actions/runs/456"):
            observed = json.loads(json.dumps(run))
            if label_written:
                observed["status"] = "completed"
                observed["conclusion"] = "cancelled"
            return observed
        if path.endswith("/issues/42/labels") and method == "POST":
            assert payload == {"labels": ["ai-review-ready"]}
            pull["labels"].append({"name": "ai-review-ready"})
            label_written = True
            return pull["labels"]
        if path.endswith("/issues/42/labels/ai-review-ready") and method == "DELETE":
            pull["labels"] = [item for item in pull["labels"] if item["name"] != "ai-review-ready"]
            return None
        raise AssertionError((method, path))

    monkeypatch.setattr(module, "api_request", fake_api_request)
    monkeypatch.setattr(
        module,
        "paginated_check_runs",
        lambda repository, head_sha, *, token: _promoter_checks(),
    )
    monkeypatch.setattr(module.CORE, "assert_newest_prt_attempt", newest)

    with pytest.raises(ValueError, match="run identity"):
        module.main()

    assert newest_checks == [1, 2]
    assert {"name": "ai-review-ready"} not in pull["labels"]
    assert not output_path.exists()


def _provider_document(provider: str = "coderabbit") -> dict[str, Any]:
    identities = {
        "coderabbit": {
            "review_login": "coderabbitai[bot]",
            "delivery_login": "coderabbitai[bot]",
            "delivery_app_id": 347564,
            "delivery_app_slug": "coderabbitai",
            "check_name": "CodeRabbit",
            "provider_mode": "native-review-app-check",
        },
        "codex": {
            "review_login": "chatgpt-codex-connector[bot]",
            "delivery_login": "chatgpt-codex-connector[bot]",
            "delivery_app_id": 1144995,
            "delivery_app_slug": "chatgpt-codex-connector",
            "check_name": None,
            "provider_mode": "native-review-app-hosted-canary-required",
        },
    }
    details = {
        **identities[provider],
        "review_id": 10,
        "review_commit_id": SHA,
        "review_state": "COMMENTED",
        "delivery_comment_id": 11,
        "hosted_canary_verified": True,
        "native_check_id": 99 if provider == "coderabbit" else 0,
        "native_check_conclusion": "success" if provider == "coderabbit" else "",
        "review_body_sha256": "f" * 64,
        "delivery_body_sha256": "0" * 64,
        "unresolved_threads": 0,
        "failure_markers": [],
    }
    return {
        "schema_version": 1,
        "provider": provider,
        "repository": "koios-ai/example",
        "repository_id": 123,
        "pull_request_number": 42,
        "head_sha": SHA,
        "base_sha": BASE_SHA,
        "checked_at": "2026-07-26T20:00:00Z",
        "evaluator": {
            "path": ".github/ci/evaluate_ai_provider.py",
            "sha256": "e" * 64,
            "source_sha": BASE_SHA,
        },
        "passed": True,
        "reason": "pass",
        "provider_evidence": details,
    }


def test_ai_publisher_requires_exact_consumer_evidence_and_runtime_tuple(
    tmp_path: Path,
) -> None:
    module = load_module(
        "publish-ai-context/publish_ai_context.py",
        "publish_ai_context",
    )
    assert module.resolve_publisher(
        ".github/workflows/coderabbit-final.yml",
        "publish-coderabbit",
    ) == ("AI / CodeRabbit final", "coderabbit")
    assert module.resolve_publisher(
        ".github/workflows/codex-final-gate.yml",
        "publish-codex",
    ) == ("AI / Codex final", "codex")
    assert module.resolve_publisher(
        ".github/workflows/ai-findings-resolved.yml",
        "publish-findings",
    ) == ("AI / findings resolved", "findings")
    with pytest.raises(ValueError):
        module.resolve_publisher(
            ".github/workflows/final-required.yml",
            "publish-coderabbit",
        )

    evidence = _provider_document()
    assert module.validate_provider_evidence(
        evidence,
        provider="coderabbit",
        repository="koios-ai/example",
        repository_id=123,
        pull_request_number=42,
        head_sha=SHA,
        base_sha=BASE_SHA,
        evaluator_result="success",
    )
    for field, value in (
        ("review_commit_id", BASE_SHA),
        ("delivery_app_id", 1144995),
        ("review_login", "attacker[bot]"),
        ("hosted_canary_verified", False),
        ("unresolved_threads", 1),
        ("failure_markers", ["review skipped"]),
    ):
        changed = json.loads(json.dumps(evidence))
        changed["provider_evidence"][field] = value
        with pytest.raises(ValueError):
            module.validate_provider_evidence(
                changed,
                provider="coderabbit",
                repository="koios-ai/example",
                repository_id=123,
                pull_request_number=42,
                head_sha=SHA,
                base_sha=BASE_SHA,
                evaluator_result="success",
            )

    evidence_dir = tmp_path / "ci-platform-ai-evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "provider-evidence.json"
    digest = _write_json(evidence_path, evidence)
    passed, observed = module.load_evidence(
        runner_temp=str(tmp_path),
        expected_digest=digest,
        provider="coderabbit",
        repository="koios-ai/example",
        repository_id=123,
        pull_request_number=42,
        head_sha=SHA,
        base_sha=BASE_SHA,
        evaluator_result="success",
    )
    assert passed is True
    assert observed == digest
    assert (
        module.load_evidence(
            runner_temp=str(tmp_path),
            expected_digest="f" * 64,
            provider="coderabbit",
            repository="koios-ai/example",
            repository_id=123,
            pull_request_number=42,
            head_sha=SHA,
            base_sha=BASE_SHA,
            evaluator_result="success",
        )[0]
        is False
    )


def test_ai_publisher_external_identity_binds_job_check_and_evidence() -> None:
    module = load_module(
        "publish-ai-context/publish_ai_context.py",
        "publish_ai_context_identity",
    )
    identity = {
        "repository": "koios-ai/example",
        "repository_id": "123",
        "pull_request_number": "42",
        "head_sha": SHA,
        "context": "AI / Codex final",
        "provider": "codex",
        "workflow_ref": ("koios-ai/example/.github/workflows/codex-final-gate.yml@refs/heads/main"),
        "workflow_sha": BASE_SHA,
        "run_id": "456",
        "run_attempt": "2",
        "job_check_run_id": "789",
        "evidence_digest": "d" * 64,
        "action_ref": PLATFORM_SHA,
        "job_id": "publish-codex",
    }
    payload = module.build_payload(identity, "success")
    assert payload["name"] == "AI / Codex final"
    assert payload["head_sha"] == SHA
    assert payload["conclusion"] == "success"
    assert payload["details_url"].endswith("/actions/runs/456/attempts/2")
    original = module.canonical_external_id(identity)
    for field in identity:
        changed = dict(identity)
        changed[field] = f"{changed[field]}x"
        assert module.canonical_external_id(changed) != original


def _live_prt_pull() -> dict[str, Any]:
    return {
        "number": 42,
        "state": "open",
        "draft": False,
        "head": {
            "sha": SHA,
            "ref": "feature/live-shape",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "labels": [{"name": "ci-final"}],
    }


def _live_prt_run(
    *,
    run_id: int = 456,
    run_number: int = 10,
    run_attempt: int = 2,
    status: str = "in_progress",
    conclusion: str | None = None,
    pull_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    workflow_id = 999
    return {
        "id": run_id,
        "url": (f"https://api.github.com/repos/koios-ai/example/actions/runs/{run_id}"),
        "html_url": (f"https://github.com/koios-ai/example/actions/runs/{run_id}"),
        "run_number": run_number,
        "run_attempt": run_attempt,
        "workflow_id": workflow_id,
        "workflow_url": (f"https://api.github.com/repos/koios-ai/example/actions/workflows/{workflow_id}"),
        "event": "pull_request_target",
        "status": status,
        "conclusion": conclusion,
        # Live REST shape: these are the PR head, not the protected base.
        "head_sha": SHA,
        "head_branch": "feature/live-shape",
        "head_commit": {"id": SHA},
        "path": ".github/workflows/final-required.yml",
        "repository": {"id": 123, "full_name": "koios-ai/example"},
        "head_repository": {"id": 123, "full_name": "koios-ai/example"},
        "referenced_workflows": [
            {
                "path": (f"koios-ai/ci-platform/.github/workflows/reusable-final.yml@{PLATFORM_SHA}"),
                "sha": PLATFORM_SHA,
            }
        ],
        "pull_requests": (
            [
                {
                    "number": 42,
                    "head": {"sha": SHA},
                    "base": {"sha": BASE_SHA},
                }
            ]
            if pull_entries is None
            else pull_entries
        ),
    }


def test_ai_publisher_requires_main_as_protected_controller_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-ai-context/publish_ai_context.py",
        "publish_ai_context_default_branch",
    )
    runtime = {
        "api_url": "https://api.github.com",
        "server_url": "https://github.com",
        "event_name": "pull_request_target",
        "action_repository": "koios-ai/ci-platform",
        "action_ref": PLATFORM_SHA,
        "workflow_repository": "koios-ai/example",
        "workflow_file_path": ".github/workflows/coderabbit-final.yml",
        "workflow_sha": BASE_SHA,
        "workflow_ref": ("koios-ai/example/.github/workflows/coderabbit-final.yml@refs/heads/main"),
        "job_id": "publish-coderabbit",
        "job_check_run_id": "789",
        "run_id": "456",
        "run_attempt": "2",
        "repository_id": "123",
    }
    pull = _live_prt_pull()
    assert module.validate_runtime(runtime, pull, "koios-ai/example") == (
        "AI / CodeRabbit final",
        "coderabbit",
    )

    release_pull = {
        **pull,
        "base": {**pull["base"], "ref": "release"},
    }
    with pytest.raises(ValueError, match="runtime identity"):
        module.validate_runtime(runtime, release_pull, "koios-ai/example")

    monkeypatch.setattr(
        module.CORE,
        "api_request",
        lambda method, path, *, token: release_pull,
    )
    with pytest.raises(ValueError, match="AI candidate"):
        module._fetch_pull(
            "koios-ai/example",
            42,
            SHA,
            token="redacted",
            required_label="ci-final",
        )


def test_publisher_accepts_live_prt_head_shape_and_binds_protected_base() -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_live_prt_shape",
    )
    runtime = {
        "run_id": "456",
        "run_attempt": "2",
        "repository_id": "123",
        "workflow_file_path": ".github/workflows/final-required.yml",
        "action_ref": PLATFORM_SHA,
    }
    run = _live_prt_run()
    module._validate_current_run(
        run,
        runtime=runtime,
        pull=_live_prt_pull(),
        repository="koios-ai/example",
        number=42,
    )

    wrong = json.loads(json.dumps(run))
    wrong["head_sha"] = BASE_SHA
    wrong["head_commit"]["id"] = BASE_SHA
    with pytest.raises(ValueError):
        module._validate_current_run(
            wrong,
            runtime=runtime,
            pull=_live_prt_pull(),
            repository="koios-ai/example",
            number=42,
        )
    wrong = json.loads(json.dumps(run))
    wrong["pull_requests"][0]["base"]["sha"] = SHA
    with pytest.raises(ValueError):
        module._validate_current_run(
            wrong,
            runtime=runtime,
            pull=_live_prt_pull(),
            repository="koios-ai/example",
            number=42,
        )
    for field, value in (
        (
            "path",
            ("koios-ai/ci-platform/.github/workflows/reusable-final.yml@refs/heads/main"),
        ),
        ("sha", BASE_SHA),
        ("ref", "refs/heads/main"),
    ):
        wrong = json.loads(json.dumps(run))
        wrong["referenced_workflows"][0][field] = value
        with pytest.raises(ValueError, match="immutable literal SHA"):
            module._validate_current_run(
                wrong,
                runtime=runtime,
                pull=_live_prt_pull(),
                repository="koios-ai/example",
                number=42,
            )


def test_publisher_rejects_older_attempt_when_newer_run_has_no_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_newest_attempt",
    )
    current = _live_prt_run()
    newer_startup_failure = _live_prt_run(
        run_id=457,
        run_number=11,
        run_attempt=1,
        status="completed",
        conclusion="startup_failure",
        pull_entries=[],
    )
    monkeypatch.setattr(
        module,
        "paginated_workflow_runs",
        lambda repository, workflow_id, *, token: [
            current,
            newer_startup_failure,
        ],
    )
    with pytest.raises(ValueError, match="superseded"):
        module.assert_newest_prt_attempt(
            current,
            pull=_live_prt_pull(),
            repository="koios-ai/example",
            token="redacted",
        )

    monkeypatch.setattr(
        module,
        "paginated_workflow_runs",
        lambda repository, workflow_id, *, token: [current],
    )
    module.assert_newest_prt_attempt(
        current,
        pull=_live_prt_pull(),
        repository="koios-ai/example",
        token="redacted",
    )


def test_publisher_ignores_newer_unrelated_label_skip_but_not_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_label_skip",
    )
    current = _live_prt_run()
    unrelated_skip = _live_prt_run(
        run_id=457,
        run_number=11,
        run_attempt=1,
        status="completed",
        conclusion="skipped",
    )
    startup_failure = _live_prt_run(
        run_id=458,
        run_number=12,
        run_attempt=1,
        status="completed",
        conclusion="startup_failure",
        pull_entries=[],
    )
    monkeypatch.setattr(
        module,
        "paginated_workflow_runs",
        lambda repository, workflow_id, *, token: [current, unrelated_skip],
    )
    module.assert_newest_prt_attempt(
        current,
        pull=_live_prt_pull(),
        repository="koios-ai/example",
        token="redacted",
    )

    monkeypatch.setattr(
        module,
        "paginated_workflow_runs",
        lambda repository, workflow_id, *, token: [
            current,
            unrelated_skip,
            startup_failure,
        ],
    )
    with pytest.raises(ValueError, match="superseded"):
        module.assert_newest_prt_attempt(
            current,
            pull=_live_prt_pull(),
            repository="koios-ai/example",
            token="redacted",
        )


def test_check_and_workflow_history_requests_are_complete_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_pagination",
    )
    paths: list[str] = []

    def fake_request(
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        ambiguous_write: bool = False,
    ) -> dict[str, Any]:
        del method, token, payload, ambiguous_write
        paths.append(path)
        if "check-runs" in path:
            return {"total_count": 0, "check_runs": []}
        return {"total_count": 0, "workflow_runs": []}

    monkeypatch.setattr(module, "api_request", fake_request)
    assert (
        module.paginated_check_runs(
            "koios-ai/example",
            SHA,
            "Security / required",
            token="redacted",
        )
        == []
    )
    assert (
        module.paginated_workflow_runs(
            "koios-ai/example",
            999,
            token="redacted",
        )
        == []
    )
    assert "filter=all" in paths[0]
    assert "per_page=100&page=1" in paths[0]
    assert "exclude_pull_requests=false" in paths[1]
    assert "per_page=100&page=1" in paths[1]


def test_publisher_refuses_redirects_and_reconciles_ambiguous_server_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_redirects",
    )

    class RedirectedResponse:
        status = 200

        def __enter__(self) -> RedirectedResponse:
            return self

        def __exit__(self, *args: Any) -> None:
            del args

        def geturl(self) -> str:
            return "https://attacker.invalid/redirected"

        def read(self) -> bytes:
            return b"{}"

    class RedirectedOpener:
        def open(self, request: Any, timeout: int) -> RedirectedResponse:
            del request, timeout
            return RedirectedResponse()

    monkeypatch.setattr(module, "_opener", lambda: RedirectedOpener())
    with pytest.raises(RuntimeError, match="redirect"):
        module.api_request(
            "GET",
            "/repos/koios-ai/example",
            token="redacted",
        )

    class FailingOpener:
        def open(self, request: Any, timeout: int) -> None:
            del timeout
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "unavailable",
                Message(),
                None,
            )

    monkeypatch.setattr(module, "_opener", lambda: FailingOpener())
    with pytest.raises(module.AmbiguousWriteError):
        module.api_request(
            "POST",
            "/repos/koios-ai/example/check-runs",
            token="redacted",
            payload={"name": "Security / required"},
            ambiguous_write=True,
        )


def test_ambiguous_cancellation_retries_until_non_success_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module(
        "publish-final-contexts/publish_final_contexts.py",
        "publisher_cancel_reconcile",
    )
    identity = {
        "repository": "koios-ai/example",
        "repository_id": "123",
        "pull_request_number": "42",
        "head_sha": SHA,
        "context": "Security / required",
        "workflow_ref": ("koios-ai/example/.github/workflows/final-required.yml@refs/heads/main"),
        "workflow_sha": BASE_SHA,
        "run_id": "456",
        "run_attempt": "2",
        "evidence_digest": "d" * 64,
        "deepsource_evidence_digest": "e" * 64,
        "action_ref": PLATFORM_SHA,
        "job_id": "publish-security",
        "job_check_run_id": "789",
    }
    payload = module.build_check_payload(identity, "success")
    calls: list[str] = []

    def request(
        method: str,
        path: str,
        *,
        token: str,
        payload: dict[str, Any] | None = None,
        ambiguous_write: bool = False,
    ) -> dict[str, Any]:
        del path, token, ambiguous_write
        calls.append(method)
        if method == "PATCH" and calls.count("PATCH") == 1:
            raise module.AmbiguousWriteError("timeout")
        if method == "GET":
            if calls.count("GET") == 1:
                return {
                    **globals_payload,
                    "app": {"id": 15368, "slug": "github-actions"},
                }
            return {
                **globals_payload,
                "conclusion": "cancelled",
                "output": {
                    "title": "Security / required: cancelled",
                    "summary": "The pull-request head changed during publication.",
                },
                "app": {"id": 15368, "slug": "github-actions"},
            }
        return {"id": 1}

    globals_payload = payload
    monkeypatch.setattr(module, "api_request", request)
    module._cancel_written_check(
        "koios-ai/example",
        1,
        payload,
        token="redacted",
    )
    assert calls == ["PATCH", "GET", "PATCH", "GET"]
