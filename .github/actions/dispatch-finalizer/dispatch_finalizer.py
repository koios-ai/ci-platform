"""Dispatch and read back one immutable exact-attempt finalizer identity."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

API_URL = "https://api.github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
SUBJECT_TITLE = re.compile(
    r"^koios-final-subject-v1\|repo=([1-9][0-9]*)\|pr=([1-9][0-9]*)"
    r"\|head=([0-9a-f]{40})\|base=([0-9a-f]{40})\|platform=([0-9a-f]{40})$"
)
GITHUB_ACTIONS_ACTOR = {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
MAX_READBACK_ATTEMPTS = 5
CONTROLLER_STATUSES = {"queued", "in_progress", "completed"}
CONTROLLER_CONCLUSIONS = {
    "success",
    "failure",
    "cancelled",
    "skipped",
    "neutral",
    "timed_out",
    "action_required",
    "stale",
    "startup_failure",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def api_request(
    method: str,
    path: str,
    *,
    token: str,
    payload: Mapping[str, Any] | None = None,
    expect_empty: bool = False,
) -> Any:
    if (
        method not in {"GET", "POST"}
        or not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or "\\" in path
        or any(character in path for character in "\r\n")
    ):
        raise ValueError("GitHub API request is outside the closed boundary")
    expected_url = f"{API_URL}{path}"
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        expected_url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "koios-ci-platform",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _opener().open(request, timeout=30) as response:
            if response.geturl() != expected_url:
                raise RuntimeError("GitHub API redirect refused")
            status = getattr(response, "status", None)
            if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 300:
                raise RuntimeError("GitHub API returned a malformed HTTP status")
            raw = response.read()
            if expect_empty and raw:
                raise RuntimeError("GitHub dispatch returned an unexpected response body")
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GitHub API {method} failed with HTTP {error.code}") from error
    except (TimeoutError, urllib.error.URLError) as error:
        raise RuntimeError(f"GitHub API {method} request failed") from error


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return int(value)


def _actor(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    projection = {key: value.get(key) for key in ("login", "id", "type")}
    return projection if projection == GITHUB_ACTIONS_ACTOR else None


def _validate_inputs(
    repository: str,
    subject_run_id: int,
    subject_run_attempt: int,
    subject_workflow_id: int,
    subject_workflow_path: str,
    finalizer_workflow_path: str,
    default_branch: str,
    platform_sha: str,
) -> None:
    if not REPOSITORY.fullmatch(repository):
        raise ValueError("repository is malformed")
    for value, field in (
        (subject_run_id, "subject run"),
        (subject_run_attempt, "subject attempt"),
        (subject_workflow_id, "subject workflow"),
    ):
        _positive_integer(value, field)
    if not FULL_SHA.fullmatch(platform_sha):
        raise ValueError("dispatch SHA is malformed")
    if (
        not WORKFLOW_PATH.fullmatch(subject_workflow_path)
        or not WORKFLOW_PATH.fullmatch(finalizer_workflow_path)
        or subject_workflow_path == finalizer_workflow_path
    ):
        raise ValueError("dispatch workflow paths are malformed or ambiguous")
    if (
        not BRANCH.fullmatch(default_branch)
        or default_branch.startswith("/")
        or default_branch.endswith("/")
        or ".." in default_branch
        or "//" in default_branch
    ):
        raise ValueError("default branch is malformed")


def _closed_workflow_runs(payload: Any) -> list[Mapping[str, Any]]:
    if not isinstance(payload, Mapping) or set(payload) != {"total_count", "workflow_runs"}:
        raise RuntimeError("controller run inventory is malformed")
    rows = payload["workflow_runs"]
    total_count = payload["total_count"]
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count < 0
        or not isinstance(rows, list)
        or total_count < len(rows)
        or len(rows) > 100
        or not all(isinstance(row, Mapping) for row in rows)
    ):
        raise RuntimeError("controller run inventory is malformed or unbounded")
    return rows


def trusted_controller_identity(
    row: Mapping[str, Any],
    expected_title: str,
    default_branch: str,
    base_sha: str,
) -> bool:
    """Bind a dispatched controller to the exact protected source commit and bot."""
    return (
        row.get("display_title") == expected_title
        and row.get("event") == "workflow_dispatch"
        and row.get("head_branch") == default_branch
        and row.get("head_sha") == base_sha
        and _actor(row.get("actor")) is not None
        and _actor(row.get("triggering_actor")) is not None
    )


def _validated_controller_run_id(row: Mapping[str, Any]) -> int:
    run_id = _positive_integer(row.get("id"), "controller run id")
    _positive_integer(row.get("workflow_id"), "controller workflow id")
    status = row.get("status")
    conclusion = row.get("conclusion")
    if (
        row.get("run_attempt") != 1
        or status not in CONTROLLER_STATUSES
        or (status == "completed" and conclusion not in CONTROLLER_CONCLUSIONS)
        or (status != "completed" and conclusion is not None)
    ):
        raise RuntimeError("controller readback is malformed")
    return run_id


def dispatch_finalizer(
    repository: str,
    subject_run_id: int,
    subject_run_attempt: int,
    subject_workflow_id: int,
    subject_workflow_path: str,
    finalizer_workflow_path: str,
    default_branch: str,
    *,
    platform_sha: str,
    token: str,
) -> int:
    _validate_inputs(
        repository,
        subject_run_id,
        subject_run_attempt,
        subject_workflow_id,
        subject_workflow_path,
        finalizer_workflow_path,
        default_branch,
        platform_sha,
    )
    repository_payload = api_request("GET", f"/repos/{repository}", token=token)
    subject = api_request(
        "GET",
        f"/repos/{repository}/actions/runs/{subject_run_id}/attempts/{subject_run_attempt}",
        token=token,
    )
    if not isinstance(repository_payload, Mapping) or not isinstance(subject, Mapping):
        raise RuntimeError("dispatch boundary readback is malformed")
    repository_id = _positive_integer(repository_payload.get("id"), "repository id")
    if repository_payload.get("full_name") != repository or repository_payload.get("default_branch") != default_branch:
        raise RuntimeError("repository/default-branch readback changed")
    title = subject.get("display_title")
    title_match = SUBJECT_TITLE.fullmatch(title) if isinstance(title, str) and len(title) <= 512 else None
    if title_match is None:
        raise RuntimeError("subject workflow title is malformed")
    title_repository_id, title_number, head_sha, base_sha, title_platform_sha = title_match.groups()
    number = _positive_integer(int(title_number), "pull request")
    if _positive_integer(int(title_repository_id), "title repository id") != repository_id:
        raise RuntimeError("subject workflow repository identity changed")
    if title_platform_sha != platform_sha:
        raise RuntimeError("subject workflow platform identity changed")
    pull = api_request("GET", f"/repos/{repository}/pulls/{number}", token=token)
    if not isinstance(pull, Mapping):
        raise RuntimeError("dispatch pull-request readback is malformed")
    head = pull.get("head")
    base = pull.get("base")
    head_repo = head.get("repo") if isinstance(head, Mapping) else None
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if (
        pull.get("number") != number
        or pull.get("state") != "open"
        or pull.get("draft") is not False
        or not isinstance(head, Mapping)
        or head.get("sha") != head_sha
        or not isinstance(base, Mapping)
        or base.get("sha") != base_sha
        or not isinstance(head_repo, Mapping)
        or not isinstance(base_repo, Mapping)
        or head_repo.get("id") != repository_id
        or base_repo.get("id") != repository_id
        or head_repo.get("full_name") != repository
        or base_repo.get("full_name") != repository
    ):
        raise RuntimeError("pull request changed before finalizer dispatch")
    expected_subject_title = (
        f"koios-final-subject-v1|repo={repository_id}|pr={number}|head={head_sha}"
        f"|base={base_sha}|platform={platform_sha}"
    )
    if (
        subject.get("id") != subject_run_id
        or subject.get("run_attempt") != subject_run_attempt
        or subject.get("workflow_id") != subject_workflow_id
        or subject.get("path")
        not in {
            subject_workflow_path,
            f"{subject_workflow_path}@{default_branch}",
            f"{subject_workflow_path}@refs/heads/{default_branch}",
        }
        or subject.get("head_branch") != default_branch
        or subject.get("head_sha") != base_sha
        or subject.get("event") != "workflow_dispatch"
        or subject.get("status") != "completed"
        or subject.get("conclusion") != "success"
        or title != expected_subject_title
        or _actor(subject.get("actor")) is None
        or _actor(subject.get("triggering_actor")) is None
    ):
        raise RuntimeError("subject workflow attempt is not the exact trusted success")

    encoded_workflow = urllib.parse.quote(finalizer_workflow_path, safe="")
    inventory_path = (
        f"/repos/{repository}/actions/workflows/{encoded_workflow}/runs?event=workflow_dispatch&per_page=100"
    )
    expected_controller_title = (
        f"koios-finalizer-v1|repo={repository_id}|pr={number}|head={head_sha}|base={base_sha}"
        f"|subject={subject_run_id}|attempt={subject_run_attempt}"
    )

    def matching(payload: Any) -> list[Mapping[str, Any]]:
        return [
            row
            for row in _closed_workflow_runs(payload)
            if trusted_controller_identity(
                row,
                expected_controller_title,
                default_branch,
                base_sha,
            )
        ]

    before = matching(api_request("GET", inventory_path, token=token))
    if len(before) > 1:
        raise RuntimeError("existing finalizer controller identity is ambiguous")
    if len(before) == 1:
        return _validated_controller_run_id(before[0])
    api_request(
        "POST",
        f"/repos/{repository}/actions/workflows/{encoded_workflow}/dispatches",
        token=token,
        payload={
            "ref": default_branch,
            "inputs": {
                "pull_request_number": str(number),
                "head_sha": head_sha,
                "base_sha": base_sha,
                "subject_run_id": str(subject_run_id),
                "subject_run_attempt": str(subject_run_attempt),
                "subject_workflow_id": str(subject_workflow_id),
                "subject_workflow_path": subject_workflow_path,
            },
        },
        expect_empty=True,
    )
    for attempt in range(1, MAX_READBACK_ATTEMPTS + 1):
        current = matching(api_request("GET", inventory_path, token=token))
        new_rows = current
        if len(new_rows) > 1:
            raise RuntimeError("finalizer dispatch created an ambiguous controller identity")
        if len(new_rows) == 1:
            return _validated_controller_run_id(new_rows[0])
        if attempt < MAX_READBACK_ATTEMPTS:
            time.sleep(attempt)
    raise RuntimeError("finalizer dispatch could not prove a new exact controller run")


def _environment_integer(name: str) -> int:
    raw = os.environ.get(name, "")
    if not raw.isdecimal() or int(raw) < 1:
        raise ValueError(f"{name} is not a positive integer")
    return int(raw)


def trusted_dispatch_caller(
    workflow_ref: str,
    repository: str,
    default_branch: str,
    *,
    event_name: str,
    actor: str,
    triggering_actor: str,
    current_run_id: int,
    current_run_attempt: int,
    subject_run_id: int,
    subject_run_attempt: int,
) -> bool:
    suffix = f"@refs/heads/{default_branch}"
    resume_ref = f"{repository}/.github/workflows/resume-finalizer-v1.yml{suffix}"
    return (
        event_name == "workflow_run"
        and workflow_ref == resume_ref
        and actor == "github-actions[bot]"
        and triggering_actor == "github-actions[bot]"
        and current_run_id != subject_run_id
        and current_run_attempt == 1
        and subject_run_attempt >= 1
    )


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    action_repository = os.environ.get("ACTION_REPOSITORY", "")
    action_ref = os.environ.get("ACTION_REF", "")
    subject_run_id = _environment_integer("INPUT_SUBJECT_RUN_ID")
    subject_run_attempt = _environment_integer("INPUT_SUBJECT_RUN_ATTEMPT")
    current_run_id = _environment_integer("GITHUB_RUN_ID")
    current_run_attempt = _environment_integer("GITHUB_RUN_ATTEMPT")
    default_branch = os.environ.get("INPUT_DEFAULT_BRANCH", "")
    if (
        not token
        or os.environ.get("GITHUB_API_URL") != API_URL
        or action_repository != ACTION_REPOSITORY
        or not FULL_SHA.fullmatch(action_ref)
        or not trusted_dispatch_caller(
            os.environ.get("GITHUB_WORKFLOW_REF", ""),
            repository,
            default_branch,
            event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
            actor=os.environ.get("GITHUB_ACTOR", ""),
            triggering_actor=os.environ.get("GITHUB_TRIGGERING_ACTOR", ""),
            current_run_id=current_run_id,
            current_run_attempt=current_run_attempt,
            subject_run_id=subject_run_id,
            subject_run_attempt=subject_run_attempt,
        )
    ):
        raise ValueError("trusted immutable dispatch runtime is unavailable")
    run_id = dispatch_finalizer(
        repository,
        subject_run_id,
        subject_run_attempt,
        _environment_integer("INPUT_SUBJECT_WORKFLOW_ID"),
        os.environ.get("INPUT_SUBJECT_WORKFLOW_PATH", ""),
        os.environ.get("INPUT_FINALIZER_WORKFLOW_PATH", ""),
        default_branch,
        platform_sha=action_ref,
        token=token,
    )
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"controller_run_id={run_id}\n")


if __name__ == "__main__":
    main()
