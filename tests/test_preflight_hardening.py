from __future__ import annotations

import importlib.util
import io
import json
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_PATH = ROOT / ".github" / "actions" / "final-preflight" / "preflight.py"
ACTION_PATH = PREFLIGHT_PATH.with_name("action.yml")

TARGET_REPOSITORY = "koios-ai/example"
ACTION_REPOSITORY = "koios-ai/ci-platform"
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
ACTION_REF = "c" * 40
WORKFLOW_ID = 456
PULL_REQUEST_NUMBER = 17


def load_preflight(name: str = "preflight_hardening") -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, PREFLIGHT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def required_run(
    *,
    run_id: int = 9001,
    run_number: int = 44,
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": WORKFLOW_ID,
        "workflow_url": (f"https://api.github.com/repos/{ACTION_REPOSITORY}/actions/workflows/{WORKFLOW_ID}"),
        "name": "Organization required integrity",
        "path": f".github/workflows/required.yml@{ACTION_REF}",
        "url": (f"https://api.github.com/repos/{TARGET_REPOSITORY}/actions/runs/{run_id}"),
        "html_url": f"https://github.com/{TARGET_REPOSITORY}/actions/runs/{run_id}",
        "head_sha": HEAD_SHA,
        "head_repository": {"full_name": TARGET_REPOSITORY},
        "head_commit": {"id": HEAD_SHA},
        "repository": {"full_name": TARGET_REPOSITORY},
        "pull_requests": [
            {
                "number": PULL_REQUEST_NUMBER,
                "head": {"sha": HEAD_SHA},
            }
        ],
        "event": "pull_request",
        "status": status,
        "conclusion": conclusion,
        "run_number": run_number,
        "run_attempt": run_attempt,
    }


def required_check(
    *,
    run_id: int = 9001,
    details_url: str | None = None,
    app_id: int = 15368,
) -> dict[str, Any]:
    return {
        "id": 7001,
        "name": "CI / required",
        "head_sha": HEAD_SHA,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": app_id, "slug": "github-actions"},
        "details_url": details_url or f"https://github.com/{TARGET_REPOSITORY}/actions/runs/{run_id}",
        "completed_at": "2026-07-26T10:00:00Z",
    }


def required_job(
    *,
    job_id: int = 8001,
    run_id: int = 9001,
    run_attempt: int = 1,
    check_run_id: int = 7001,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": (f"https://api.github.com/repos/{TARGET_REPOSITORY}/actions/runs/{run_id}"),
        "head_sha": HEAD_SHA,
        "name": "CI / required",
        "status": "completed",
        "conclusion": "success",
        "check_run_url": (f"https://api.github.com/repos/{TARGET_REPOSITORY}/check-runs/{check_run_id}"),
        "url": (f"https://api.github.com/repos/{TARGET_REPOSITORY}/actions/jobs/{job_id}"),
        "html_url": (f"https://github.com/{TARGET_REPOSITORY}/actions/runs/{run_id}/job/{job_id}"),
    }


def pull_request() -> dict[str, Any]:
    return {
        "number": PULL_REQUEST_NUMBER,
        "state": "open",
        "draft": False,
        "head": {
            "sha": HEAD_SHA,
            "repo": {"id": 123, "full_name": TARGET_REPOSITORY},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 123, "full_name": TARGET_REPOSITORY},
        },
        "labels": [{"name": "ci-final"}],
    }


def test_action_binds_workflow_identity_and_action_ref() -> None:
    """Catches omitting the immutable source workflow identity at the action boundary."""
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))

    assert "required_fast_workflow_id" in action["inputs"]
    step = action["runs"]["steps"][0]
    assert step["env"]["INPUT_REQUIRED_FAST_WORKFLOW_ID"] == "${{ inputs.required_fast_workflow_id }}"
    assert step["env"]["TRUSTED_ACTION_REF"] == "${{ github.action_ref }}"
    assert step["env"]["TRUSTED_ACTION_REPOSITORY"] == "${{ github.action_repository }}"


@pytest.mark.parametrize(
    "url",
    [
        f"http://github.com/{TARGET_REPOSITORY}/actions/runs/9001",
        f"https://github.com.evil.test/{TARGET_REPOSITORY}/actions/runs/9001",
        "https://github.com/attacker/example/actions/runs/9001",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001?attempt=1",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001#result",
        f"https://user@github.com/{TARGET_REPOSITORY}/actions/runs/9001",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/jobs/8001",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001/",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001/attempts/1",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001?check_suite=1",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001#step:1",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/09001/job/8001",
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/08001",
    ],
)
def test_parse_run_id_rejects_non_exact_repo_bound_urls(url: str) -> None:
    """Catches a lookalike or decorated URL being accepted as trusted run evidence."""
    module = load_preflight(f"preflight_url_{abs(hash(url))}")

    with pytest.raises(ValueError):
        module.parse_run_id(
            url,
            repository=TARGET_REPOSITORY,
            server_url="https://github.com",
        )


def test_parse_run_id_accepts_only_the_exact_run_page() -> None:
    """Catches rejecting the one canonical repository-bound workflow run URL."""
    module = load_preflight("preflight_url_valid")

    assert (
        module.parse_run_id(
            f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001",
            repository=TARGET_REPOSITORY,
            server_url="https://github.com",
        )
        == 9001
    )


def test_parse_actions_details_url_accepts_exact_job_page() -> None:
    """Catches rejecting GitHub Actions' canonical job-bound check details URL."""
    module = load_preflight("preflight_job_url_valid")

    assert module.parse_actions_details_url(
        f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001",
        repository=TARGET_REPOSITORY,
        server_url="https://github.com",
    ) == (9001, 8001)


def test_required_check_requires_github_actions_slug_and_id() -> None:
    """Catches an App reusing GitHub Actions' slug without its immutable App ID."""
    module = load_preflight("preflight_app_identity")

    selected = module.select_required_check(
        [required_check()],
        required_context="CI / required",
        head_sha=HEAD_SHA,
        run_id=9001,
        run_attempt=1,
        repository=TARGET_REPOSITORY,
        server_url="https://github.com",
        token="redacted",
        api_url="https://api.github.com",
    )
    assert selected["id"] == 7001

    with pytest.raises(ValueError):
        module.select_required_check(
            [required_check(app_id=999)],
            required_context="CI / required",
            head_sha=HEAD_SHA,
            run_id=9001,
            run_attempt=1,
            repository=TARGET_REPOSITORY,
            server_url="https://github.com",
            token="redacted",
            api_url="https://api.github.com",
        )


def test_job_page_check_is_resolved_and_bound_to_selected_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches trusting a job-page check without resolving its run and check identity."""
    module = load_preflight("preflight_job_binding")
    check = required_check(details_url=(f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001"))
    requested: list[str] = []

    def request(
        method: str,
        path: str,
        *,
        token: str,
        api_url: str,
        payload: Any = None,
    ) -> dict[str, Any]:
        del method, token, api_url, payload
        requested.append(path)
        return required_job()

    monkeypatch.setattr(module, "api_request", request)
    selected = module.select_required_check(
        [check],
        required_context="CI / required",
        head_sha=HEAD_SHA,
        run_id=9001,
        run_attempt=1,
        repository=TARGET_REPOSITORY,
        server_url="https://github.com",
        token="redacted",
        api_url="https://api.github.com",
    )

    assert selected == check
    assert requested == [
        f"/repos/{TARGET_REPOSITORY}/actions/jobs/8001",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 8002),
        ("run_id", 9002),
        ("run_attempt", 2),
        ("run_url", "https://api.github.com/repos/attacker/repo/actions/runs/9001"),
        ("head_sha", BASE_SHA),
        ("name", "CI / attacker"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("check_run_url", "https://api.github.com/repos/koios-ai/example/check-runs/9"),
        ("url", "https://api.github.com/repos/koios-ai/example/actions/jobs/9"),
        ("html_url", "https://github.com/koios-ai/example/actions/runs/9001/job/9"),
    ],
)
def test_job_binding_rejects_wrong_run_attempt_head_or_check(
    field: str,
    value: Any,
) -> None:
    """Catches a job from another run, attempt, head, or check being accepted."""
    module = load_preflight(f"preflight_job_field_{field}")
    job = required_job()
    job[field] = value

    with pytest.raises(ValueError):
        module.validate_job_binding(
            job,
            required_check(details_url=(f"https://github.com/{TARGET_REPOSITORY}/actions/runs/9001/job/8001")),
            job_id=8001,
            run_id=9001,
            run_attempt=1,
            head_sha=HEAD_SHA,
            repository=TARGET_REPOSITORY,
        )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_api_request_refuses_redirect_status(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    """Catches the centralized API transport following any redirect class."""
    module = load_preflight(f"preflight_redirect_status_{status}")
    url = "https://api.github.com/repos/koios-ai/example"

    def redirect(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise module.urllib.error.HTTPError(
            url,
            status,
            "redirect",
            {"Location": "https://attacker.invalid/collect"},
            None,
        )

    class RedirectingOpener:
        open = staticmethod(redirect)

    monkeypatch.setattr(module, "API_OPENER", RedirectingOpener(), raising=False)
    monkeypatch.setattr(module.urllib.request, "urlopen", redirect)

    with pytest.raises(RuntimeError, match="redirect"):
        module.api_request(
            "GET",
            "/repos/koios-ai/example",
            token="redacted",
            api_url="https://api.github.com",
        )


def test_api_request_rejects_changed_final_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches an already-followed redirect even if a transport returns HTTP 200."""
    module = load_preflight("preflight_redirect_final_url")

    class RedirectedResponse:
        status = 200

        def __enter__(self) -> RedirectedResponse:
            return self

        def __exit__(self, *args: Any) -> None:
            del args

        @staticmethod
        def geturl() -> str:
            return "https://attacker.invalid/collect"

        @staticmethod
        def read() -> bytes:
            return b"{}"

    class RedirectedOpener:
        @staticmethod
        def open(*args: Any, **kwargs: Any) -> RedirectedResponse:
            del args, kwargs
            return RedirectedResponse()

    monkeypatch.setattr(module, "API_OPENER", RedirectedOpener(), raising=False)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        RedirectedOpener.open,
    )

    with pytest.raises(RuntimeError, match="redirect"):
        module.api_request(
            "GET",
            "/repos/koios-ai/example",
            token="redacted",
            api_url="https://api.github.com",
        )


def test_api_transport_never_opens_redirect_target() -> None:
    """Catches refusing a redirect only after the transport already followed it."""
    module = load_preflight("preflight_redirect_transport")
    opened: list[str] = []

    class RedirectResponse(urllib.response.addinfourl):
        msg: str

    class RedirectTransport(urllib.request.BaseHandler):
        handler_order = 100

        def https_open(
            self,
            request: urllib.request.Request,
        ) -> urllib.response.addinfourl:
            opened.append(request.full_url)
            headers = Message()
            if len(opened) == 1:
                headers["Location"] = "https://attacker.invalid/collect"
                status, body, message = 302, b"", "Found"
            else:
                status, body, message = 200, b"{}", "OK"
            response = RedirectResponse(
                io.BytesIO(body),
                headers,
                request.full_url,
                status,
            )
            response.msg = message
            return response

    module.API_OPENER.add_handler(RedirectTransport())

    with pytest.raises(RuntimeError, match="redirect"):
        module.api_request(
            "GET",
            "/repos/koios-ai/example",
            token="must-not-leave-api-github-com",
            api_url="https://api.github.com",
        )
    assert opened == ["https://api.github.com/repos/koios-ai/example"]


def test_latest_matching_run_attempt_must_itself_succeed() -> None:
    """Catches accepting an older success after the newest attempt failed or is pending."""
    module = load_preflight("preflight_latest_attempt")
    old_success = required_run(run_id=9001, run_number=44, run_attempt=1)
    newest_pending = required_run(
        run_id=9001,
        run_number=44,
        run_attempt=2,
        status="in_progress",
        conclusion=None,
    )

    with pytest.raises(ValueError, match="newest"):
        module.select_latest_required_run(
            [old_success, newest_pending],
            workflow_id=WORKFLOW_ID,
            repository=TARGET_REPOSITORY,
            head_sha=HEAD_SHA,
            pull_request_number=PULL_REQUEST_NUMBER,
            action_ref=ACTION_REF,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", WORKFLOW_ID + 1),
        ("workflow_url", "https://api.github.com/repos/attacker/ci/actions/workflows/456"),
        ("path", ".github/workflows/other.yml@" + ACTION_REF),
        ("path", ".github/workflows/required.yml@" + ("d" * 40)),
        ("repository.full_name", "attacker/example"),
        ("head_repository.full_name", "attacker/example"),
        ("head_commit.id", BASE_SHA),
        ("pull_requests", [{"number": 99}]),
        ("event", "push"),
        ("status", "queued"),
        ("conclusion", "failure"),
    ],
)
def test_required_run_rejects_wrong_source_target_or_result(
    field: str,
    value: Any,
) -> None:
    """Catches accepting evidence from a different workflow, target, PR, or result."""
    module = load_preflight(f"preflight_run_identity_{field.replace('.', '_')}")
    run = required_run()
    target: Any = run
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value

    with pytest.raises(ValueError):
        module.validate_required_run(
            run,
            workflow_id=WORKFLOW_ID,
            repository=TARGET_REPOSITORY,
            head_sha=HEAD_SHA,
            pull_request_number=PULL_REQUEST_NUMBER,
            action_ref=ACTION_REF,
        )


def test_paginated_items_reads_every_page_and_rejects_malformed_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches first-page-only trust and silently treating malformed JSON as empty."""
    module = load_preflight("preflight_pagination")
    calls: list[str] = []

    def request(
        method: str,
        path: str,
        *,
        token: str,
        api_url: str,
        payload: Any = None,
    ) -> dict[str, Any]:
        del method, token, api_url, payload
        calls.append(path)
        if path.endswith("&page=1"):
            return {"total_count": 101, "check_runs": [{"id": value} for value in range(100)]}
        return {"total_count": 101, "check_runs": [{"id": 100}]}

    monkeypatch.setattr(module, "api_request", request)
    items = module.paginated_items(
        "/repos/koios-ai/example/commits/" + HEAD_SHA + "/check-runs?filter=all",
        "check_runs",
        token="redacted",
        api_url="https://api.github.com",
    )
    assert len(items) == 101
    assert len(calls) == 2

    monkeypatch.setattr(
        module,
        "api_request",
        lambda *args, **kwargs: {"total_count": 1, "check_runs": "not-a-list"},
    )
    with pytest.raises(RuntimeError, match="malformed"):
        module.paginated_items(
            "/repos/koios-ai/example/commits/" + HEAD_SHA + "/check-runs?filter=all",
            "check_runs",
            token="redacted",
            api_url="https://api.github.com",
        )


def test_paginated_items_fails_closed_at_the_page_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches silently truncating a result set that exceeds the bounded API walk."""
    module = load_preflight("preflight_pagination_cap")
    monkeypatch.setattr(module, "MAX_API_PAGES", 2, raising=False)
    monkeypatch.setattr(
        module,
        "api_request",
        lambda *args, **kwargs: {
            "total_count": 300,
            "workflow_runs": [{"id": value} for value in range(100)],
        },
    )

    with pytest.raises(RuntimeError, match="bounded page limit"):
        module.paginated_items(
            "/repos/koios-ai/example/actions/runs?head_sha=" + HEAD_SHA,
            "workflow_runs",
            token="redacted",
            api_url="https://api.github.com",
        )


def test_main_refetches_pr_and_rejects_state_change_before_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches emitting ready outputs after the label or PR state changed mid-flight."""
    module = load_preflight("preflight_pr_refetch")
    output_path = tmp_path / "outputs.txt"
    initial = pull_request()
    changed = json.loads(json.dumps(initial))
    changed["labels"] = []
    pull_reads = 0

    def request(
        method: str,
        path: str,
        *,
        token: str,
        api_url: str,
        payload: Any = None,
    ) -> Any:
        nonlocal pull_reads
        del method, token, api_url, payload
        if path == f"/repos/{TARGET_REPOSITORY}/pulls/{PULL_REQUEST_NUMBER}":
            pull_reads += 1
            return initial if pull_reads == 1 else changed
        if path == f"/repos/{ACTION_REPOSITORY}/actions/workflows/{WORKFLOW_ID}":
            return {
                "id": WORKFLOW_ID,
                "path": ".github/workflows/required.yml",
                "state": "active",
                "url": (f"https://api.github.com/repos/{ACTION_REPOSITORY}/actions/workflows/{WORKFLOW_ID}"),
            }
        if path == f"/repos/{TARGET_REPOSITORY}/actions/runs/9001":
            return required_run()
        raise AssertionError(f"unexpected direct API request: {path}")

    def pages(
        path: str,
        key: str | None,
        *,
        token: str,
        api_url: str,
    ) -> list[Any]:
        del token, api_url
        if key == "workflow_runs":
            return [required_run()]
        if key == "check_runs":
            return [required_check()]
        if key is None and path.endswith(f"/pulls/{PULL_REQUEST_NUMBER}/files"):
            return [{"filename": "src/widget.py"}]
        raise AssertionError(f"unexpected pagination request: {path} ({key})")

    monkeypatch.setattr(module, "api_request", request)
    monkeypatch.setattr(module, "paginated_items", pages)
    environment = {
        "GH_TOKEN": "test-token-that-must-not-appear-in-errors",
        "GITHUB_REPOSITORY": TARGET_REPOSITORY,
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
        "TRUSTED_ACTION_REPOSITORY": ACTION_REPOSITORY,
        "TRUSTED_ACTION_REF": ACTION_REF,
        "INPUT_PULL_REQUEST_NUMBER": str(PULL_REQUEST_NUMBER),
        "INPUT_EVENT_HEAD_SHA": HEAD_SHA,
        "INPUT_EVENT_BASE_SHA": BASE_SHA,
        "INPUT_REQUIRED_FAST_CONTEXT": "CI / required",
        "INPUT_REQUIRED_FAST_WORKFLOW_ID": str(WORKFLOW_ID),
        "GITHUB_OUTPUT": str(output_path),
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    with pytest.raises(ValueError):
        module.main()
    assert pull_reads == 2
    assert not output_path.exists()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_API_URL", "https://github.example/api/v3"),
        ("GITHUB_SERVER_URL", "https://github.example"),
        ("TRUSTED_ACTION_REPOSITORY", "attacker/ci-platform"),
        ("TRUSTED_ACTION_REF", "main"),
    ],
)
def test_main_rejects_non_github_or_mutable_action_context(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    """Catches redirecting API trust or executing the action from a mutable source."""
    module = load_preflight(f"preflight_context_{key}")
    environment = {
        "GH_TOKEN": "test-token-that-must-not-appear-in-errors",
        "GITHUB_REPOSITORY": TARGET_REPOSITORY,
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
        "TRUSTED_ACTION_REPOSITORY": ACTION_REPOSITORY,
        "TRUSTED_ACTION_REF": ACTION_REF,
        "INPUT_PULL_REQUEST_NUMBER": str(PULL_REQUEST_NUMBER),
        "INPUT_EVENT_HEAD_SHA": HEAD_SHA,
        "INPUT_EVENT_BASE_SHA": BASE_SHA,
        "INPUT_REQUIRED_FAST_CONTEXT": "CI / required",
        "INPUT_REQUIRED_FAST_WORKFLOW_ID": str(WORKFLOW_ID),
    }
    environment[key] = value
    for name, item in environment.items():
        monkeypatch.setenv(name, item)

    with pytest.raises(ValueError):
        module.main()
