"""Promote one exact PR head after owned Security and Coverage checks pass."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from types import ModuleType
from typing import Any

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
EXTERNAL_ID = re.compile(r"^ci-platform-final:v1:[0-9a-f]{64}:(security-required|coverage-required)$")
API_URL = "https://api.github.com"
SERVER_URL = "https://github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
DEFAULT_BRANCH = "main"
WORKFLOW_PATH = ".github/workflows/final-required.yml"
REUSABLE_WORKFLOW_PATH = "koios-ai/ci-platform/.github/workflows/reusable-final.yml"
GITHUB_ACTIONS_APP = {"id": 15368, "slug": "github-actions"}
FINAL_CONTEXTS = {
    "Security / required": "security-required",
    "Coverage / required": "coverage-required",
}
READY_LABEL = "ai-review-ready"


def _load_core() -> ModuleType:
    path = pathlib.Path(__file__).resolve().parents[1] / "publish-final-contexts" / "publish_final_contexts.py"
    spec = importlib.util.spec_from_file_location("ci_platform_promoter_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("central publisher core is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CORE = _load_core()


class AmbiguousWriteError(RuntimeError):
    """GitHub may have accepted a label mutation whose response was lost."""


class ApiNotFoundError(RuntimeError):
    """The exact GitHub object does not exist."""


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
    ambiguous_write: bool = False,
) -> Any:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or "\\" in path
        or any(character in path for character in "\r\n")
    ):
        raise ValueError("GitHub API path is not repository-relative")
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "koios-ci-platform-promoter",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _opener().open(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise RuntimeError("GitHub API redirect refused")
            status = getattr(response, "status", None)
            if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 300:
                raise RuntimeError("GitHub API returned a malformed HTTP status")
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as error:
        if ambiguous_write and method in {"DELETE", "POST"} and (error.code in {408, 425, 429} or error.code >= 500):
            raise AmbiguousWriteError("GitHub label write result is ambiguous") from error
        if 300 <= error.code < 400:
            raise RuntimeError("GitHub API redirect refused") from error
        if method in {"DELETE", "GET"} and error.code == 404:
            raise ApiNotFoundError(f"GitHub API object not found: {path}") from error
        raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
    except (TimeoutError, urllib.error.URLError) as error:
        if ambiguous_write and method in {"DELETE", "POST"}:
            raise AmbiguousWriteError("GitHub label write result is ambiguous") from error
        raise RuntimeError(f"GitHub API {method} request failed") from error


def _labels(pull: Mapping[str, Any]) -> set[str]:
    values = pull.get("labels")
    if not isinstance(values, list):
        raise ValueError("pull request labels are malformed")
    labels = {str(item["name"]) for item in values if isinstance(item, Mapping) and isinstance(item.get("name"), str)}
    if len(labels) != len(values):
        raise ValueError("pull request labels are malformed")
    return labels


def validate_candidate(
    pull: Mapping[str, Any],
    *,
    repository: str,
    head_sha: str,
    require_ready: bool,
) -> None:
    if not FULL_SHA.fullmatch(head_sha):
        raise ValueError("expected head is not a full lowercase SHA")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise ValueError("pull request head/base metadata is missing")
    if base.get("ref") != DEFAULT_BRANCH:
        raise ValueError("pull request does not target the protected default branch")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if (
        pull.get("state") != "open"
        or pull.get("draft") is not False
        or head.get("sha") != head_sha
        or not isinstance(head_repo, Mapping)
        or not isinstance(base_repo, Mapping)
        or head_repo.get("full_name") != repository
        or base_repo.get("full_name") != repository
        or not isinstance(head_repo.get("id"), int)
        or head_repo.get("id") != base_repo.get("id")
    ):
        raise ValueError("pull request changed or is not same-repository")
    labels = _labels(pull)
    if "ci-final" not in labels:
        raise ValueError("ci-final label is absent")
    if require_ready != (READY_LABEL in labels):
        raise ValueError("ai-review-ready label state is not expected")


def select_successful_final_checks(
    checks: list[Mapping[str, Any]],
    *,
    repository: str,
    head_sha: str,
    run_id: int,
    run_attempt: int,
    workflow_sha: str,
    action_ref: str,
) -> list[Mapping[str, Any]]:
    if (
        not FULL_SHA.fullmatch(head_sha)
        or not FULL_SHA.fullmatch(workflow_sha)
        or not FULL_SHA.fullmatch(action_ref)
        or run_id < 1
        or run_attempt < 1
    ):
        raise ValueError("final-check selector identity is malformed")
    details_url = f"{SERVER_URL}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    selected: list[Mapping[str, Any]] = []
    for context, suffix in FINAL_CONTEXTS.items():
        matching = []
        for check in checks:
            app = check.get("app")
            output = check.get("output")
            summary = output.get("summary") if isinstance(output, Mapping) else None
            external_id = check.get("external_id")
            if (
                check.get("name") == context
                and check.get("head_sha") == head_sha
                and check.get("status") == "completed"
                and check.get("conclusion") == "success"
                and check.get("details_url") == details_url
                and isinstance(check.get("id"), int)
                and isinstance(app, Mapping)
                and app.get("id") == GITHUB_ACTIONS_APP["id"]
                and app.get("slug") == GITHUB_ACTIONS_APP["slug"]
                and isinstance(external_id, str)
                and EXTERNAL_ID.fullmatch(external_id)
                and external_id.endswith(f":{suffix}")
                and isinstance(summary, str)
                and f"Workflow SHA: `{workflow_sha}`." in summary
                and f"Platform SHA: `{action_ref}`." in summary
            ):
                matching.append(check)
        if len(matching) != 1:
            raise ValueError(f"exact same-run owned final check is absent or ambiguous: {context}")
        selected.append(matching[0])
    return selected


def paginated_check_runs(
    repository: str,
    head_sha: str,
    *,
    token: str,
) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (f"/repos/{repository}/commits/{head_sha}/check-runs?filter=all&per_page=100&page={page}"),
            token=token,
        )
        items = payload.get("check_runs", []) if isinstance(payload, Mapping) else None
        total = payload.get("total_count") if isinstance(payload, Mapping) else None
        if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
            raise RuntimeError("GitHub returned malformed check-run pagination")
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or (expected_total is not None and total != expected_total)
        ):
            raise RuntimeError("GitHub returned malformed check-run total")
        expected_total = total
        values.extend(items)
        if len(items) < 100:
            if len(values) != expected_total:
                raise RuntimeError("GitHub check-run pagination was truncated")
            return values
    raise RuntimeError("check-run pagination exceeded the bounded page limit")


def _fetch_pull(
    repository: str,
    number: int,
    head_sha: str,
    *,
    token: str,
    require_ready: bool,
) -> Mapping[str, Any]:
    pull = api_request(
        "GET",
        f"/repos/{repository}/pulls/{number}",
        token=token,
    )
    if not isinstance(pull, Mapping) or pull.get("number") != number:
        raise RuntimeError("GitHub returned malformed pull request metadata")
    validate_candidate(
        pull,
        repository=repository,
        head_sha=head_sha,
        require_ready=require_ready,
    )
    return pull


def validate_runtime(
    runtime: Mapping[str, str],
    pull: Mapping[str, Any],
    repository: str,
) -> None:
    base = pull["base"]
    assert isinstance(base, Mapping)
    base_repo = base.get("repo")
    if (
        runtime.get("api_url") != API_URL
        or runtime.get("server_url") != SERVER_URL
        or runtime.get("event_name") != "pull_request_target"
        or runtime.get("action_repository") != ACTION_REPOSITORY
        or not FULL_SHA.fullmatch(runtime.get("action_ref", ""))
        or runtime.get("job_id") != "promote-ai-review"
        or runtime.get("workflow_repository") != repository
        or runtime.get("workflow_file_path") != WORKFLOW_PATH
        or runtime.get("workflow_sha") != base.get("sha")
        or runtime.get("workflow_ref") != f"{repository}/{WORKFLOW_PATH}@refs/heads/{DEFAULT_BRANCH}"
        or not isinstance(base_repo, Mapping)
        or str(base_repo.get("id")) != runtime.get("repository_id")
    ):
        raise ValueError("promoter runtime workflow or action identity is invalid")
    for field in ("run_id", "run_attempt", "repository_id"):
        value = runtime.get(field, "")
        if not value.isdecimal() or int(value) < 1:
            raise ValueError(f"promoter runtime identifier is invalid: {field}")


def validate_run(
    run: Mapping[str, Any],
    *,
    runtime: Mapping[str, str],
    pull: Mapping[str, Any],
    repository: str,
    number: int,
) -> None:
    head = pull["head"]
    base = pull["base"]
    assert isinstance(head, Mapping) and isinstance(base, Mapping)
    pull_entries = run.get("pull_requests")
    referenced = run.get("referenced_workflows")
    repository_payload = run.get("repository")
    head_repository = run.get("head_repository")
    expected_reusable = f"{REUSABLE_WORKFLOW_PATH}@{runtime['action_ref']}"
    if (
        not isinstance(pull_entries, list)
        or len(pull_entries) != 1
        or not isinstance(pull_entries[0], Mapping)
        or pull_entries[0].get("number") != number
        or not isinstance(pull_entries[0].get("head"), Mapping)
        or pull_entries[0]["head"].get("sha") != head.get("sha")
        or not isinstance(pull_entries[0].get("base"), Mapping)
        or pull_entries[0]["base"].get("sha") != base.get("sha")
        or not isinstance(referenced, list)
        or len(referenced) != 1
        or not isinstance(referenced[0], Mapping)
        or referenced[0].get("path") != expected_reusable
        or referenced[0].get("sha") != runtime["action_ref"]
        or referenced[0].get("ref") is not None
        or run.get("id") != int(runtime["run_id"])
        or run.get("run_attempt") != int(runtime["run_attempt"])
        or run.get("event") != "pull_request_target"
        or run.get("status") != "in_progress"
        or run.get("conclusion") is not None
        or run.get("head_sha") != head.get("sha")
        or run.get("head_branch") != head.get("ref")
        or run.get("path") != WORKFLOW_PATH
        or not isinstance(run.get("workflow_id"), int)
        or not isinstance(run.get("run_number"), int)
        or not isinstance(repository_payload, Mapping)
        or repository_payload.get("full_name") != repository
        or str(repository_payload.get("id")) != runtime["repository_id"]
        or not isinstance(head_repository, Mapping)
        or head_repository.get("full_name") != repository
        or str(head_repository.get("id")) != runtime["repository_id"]
    ):
        raise ValueError("promoter Actions run identity is invalid")


def _labels_present(pull: Mapping[str, Any]) -> bool:
    return READY_LABEL in _labels(pull)


def _rollback_label(repository: str, number: int, *, token: str) -> None:
    encoded = urllib.parse.quote(READY_LABEL, safe="")
    with contextlib.suppress(AmbiguousWriteError, ApiNotFoundError):
        api_request(
            "DELETE",
            f"/repos/{repository}/issues/{number}/labels/{encoded}",
            token=token,
            ambiguous_write=True,
        )
    pull = api_request(
        "GET",
        f"/repos/{repository}/pulls/{number}",
        token=token,
    )
    if not isinstance(pull, Mapping) or _labels_present(pull):
        raise RuntimeError("ai-review-ready rollback could not be confirmed")


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    raw_number = os.environ.get("INPUT_PULL_REQUEST_NUMBER", "")
    head_sha = os.environ.get("INPUT_EXPECTED_HEAD_SHA", "")
    if (
        not token
        or "/" not in repository
        or not raw_number.isdecimal()
        or int(raw_number) < 1
        or not FULL_SHA.fullmatch(head_sha)
        or os.environ.get("INPUT_SECURITY_CONCLUSION") != "success"
        or os.environ.get("INPUT_COVERAGE_CONCLUSION") != "success"
    ):
        raise ValueError("promoter inputs are incomplete or not successful")
    number = int(raw_number)
    runtime = {
        "action_ref": os.environ.get("ACTION_REF", ""),
        "action_repository": os.environ.get("ACTION_REPOSITORY", ""),
        "api_url": os.environ.get("RUNTIME_API_URL", ""),
        "server_url": os.environ.get("RUNTIME_SERVER_URL", ""),
        "event_name": os.environ.get("RUNTIME_EVENT_NAME", ""),
        "job_id": os.environ.get("RUNTIME_JOB_ID", ""),
        "run_id": os.environ.get("RUNTIME_RUN_ID", ""),
        "run_attempt": os.environ.get("RUNTIME_RUN_ATTEMPT", ""),
        "repository_id": os.environ.get("RUNTIME_REPOSITORY_ID", ""),
        "workflow_ref": os.environ.get("RUNTIME_WORKFLOW_REF", ""),
        "workflow_sha": os.environ.get("RUNTIME_WORKFLOW_SHA", ""),
        "workflow_repository": os.environ.get("RUNTIME_WORKFLOW_REPOSITORY", ""),
        "workflow_file_path": os.environ.get("RUNTIME_WORKFLOW_FILE_PATH", ""),
    }
    pull = _fetch_pull(
        repository,
        number,
        head_sha,
        token=token,
        require_ready=False,
    )
    validate_runtime(runtime, pull, repository)
    run = api_request(
        "GET",
        f"/repos/{repository}/actions/runs/{runtime['run_id']}",
        token=token,
    )
    if not isinstance(run, Mapping):
        raise RuntimeError("GitHub returned malformed Actions run metadata")
    validate_run(
        run,
        runtime=runtime,
        pull=pull,
        repository=repository,
        number=number,
    )
    CORE.assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )
    select_successful_final_checks(
        paginated_check_runs(repository, head_sha, token=token),
        repository=repository,
        head_sha=head_sha,
        run_id=int(runtime["run_id"]),
        run_attempt=int(runtime["run_attempt"]),
        workflow_sha=runtime["workflow_sha"],
        action_ref=runtime["action_ref"],
    )
    pull = _fetch_pull(
        repository,
        number,
        head_sha,
        token=token,
        require_ready=False,
    )
    run = api_request(
        "GET",
        f"/repos/{repository}/actions/runs/{runtime['run_id']}",
        token=token,
    )
    if not isinstance(run, Mapping):
        raise RuntimeError("GitHub returned malformed pre-write run metadata")
    validate_run(
        run,
        runtime=runtime,
        pull=pull,
        repository=repository,
        number=number,
    )
    CORE.assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )

    write_started = False
    try:
        write_started = True
        with contextlib.suppress(AmbiguousWriteError):
            api_request(
                "POST",
                f"/repos/{repository}/issues/{number}/labels",
                token=token,
                payload={"labels": [READY_LABEL]},
                ambiguous_write=True,
            )
        promoted = _fetch_pull(
            repository,
            number,
            head_sha,
            token=token,
            require_ready=True,
        )
        run = api_request(
            "GET",
            f"/repos/{repository}/actions/runs/{runtime['run_id']}",
            token=token,
        )
        if not isinstance(run, Mapping):
            raise RuntimeError("GitHub returned malformed post-write run metadata")
        validate_run(
            run,
            runtime=runtime,
            pull=promoted,
            repository=repository,
            number=number,
        )
    except (ValueError, RuntimeError):
        if write_started:
            _rollback_label(repository, number, token=token)
        raise
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("promoted=true\n")


if __name__ == "__main__":
    main()
