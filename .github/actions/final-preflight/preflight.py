"""Trusted metadata-only preflight for the reusable final CI lane."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

API_URL = "https://api.github.com"
SERVER_URL = "https://github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
DEFAULT_BRANCH = "main"
REQUIRED_WORKFLOW_NAME = "Organization required integrity"
REQUIRED_WORKFLOW_PATH = ".github/workflows/required.yml"
REQUIRED_CONTEXT = "CI / required"
GITHUB_ACTIONS_APP_ID = 15368
MAX_API_PAGES = 100
PAGE_SIZE = 100

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CRITICAL_MARKERS = (
    "src/features/",
    "src/inference/",
    "src/training/",
    "src/validation/",
    "src/orchestrator/",
    "src/deployment/",
    "leakage",
    "lineage",
    "schema",
    "model_registry",
    "prediction",
)
CRITICAL_EXACT_PATHS = {
    ".bandit",
    ".coderabbit.yaml",
    ".deepsource.toml",
    ".github/ci-platform-test-policy.json",
    ".mypy.ini",
    ".ruff.toml",
    ".semgrep.yml",
    ".semgrep.yaml",
    "bandit.yaml",
    "bandit.yml",
    "mypy.ini",
    "pyproject.toml",
    "pytest.ini",
    "quality_debt.yml",
    "ruff.toml",
    "scripts/install_hooks.py",
    "scripts/sync_venvs.sh",
    "setup.cfg",
    "tools/check_coverage_ratchet.py",
    "tools/check_data_quality_contract.py",
    "tools/check_docstring_contracts.py",
    "tools/check_module_coverage.py",
    "tools/check_rebuild_contract.py",
    "tools/check_schema_contract.py",
    "tools/normalize_coverage_paths.py",
    "tox.ini",
}
CRITICAL_PREFIXES = (
    ".github/actions/",
    ".github/ci/",
    ".github/workflows/",
    "tests/",
)


class RefuseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent credentials from following any GitHub API redirect."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request:
        del request, file_pointer, code, message, headers, new_url
        raise RuntimeError("GitHub API redirect refused")


API_OPENER = urllib.request.build_opener(RefuseRedirectHandler())


def _require_sha(value: str, name: str) -> str:
    if not FULL_SHA.fullmatch(value):
        raise ValueError(f"{name} is not a full lowercase commit SHA")
    return value


def _require_positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} is not a positive integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.isdecimal() and not value.startswith("0"):
        parsed = int(value)
    else:
        raise ValueError(f"{name} is not a positive integer")
    if parsed < 1:
        raise ValueError(f"{name} is not a positive integer")
    return parsed


def _require_repository(value: str) -> str:
    if not REPOSITORY_NAME.fullmatch(value) or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("trusted repository context is malformed")
    return value


def _mapping_full_name(value: Any, name: str) -> str:
    if not isinstance(value, Mapping) or not isinstance(value.get("full_name"), str):
        raise ValueError(f"{name} metadata is missing")
    return str(value["full_name"])


def canonical_changed_files_digest(paths: Iterable[str]) -> str:
    canonical = "".join(f"{path}\n" for path in sorted(set(paths)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def classify_profile(paths: Iterable[str]) -> str:
    lowered = [path.lower() for path in paths]
    if any(
        path in CRITICAL_EXACT_PATHS
        or path.startswith(CRITICAL_PREFIXES)
        or pathlib.PurePosixPath(path).name.startswith(("constraints", "requirements"))
        or any(marker in path for marker in CRITICAL_MARKERS)
        for path in lowered
    ):
        return "critical-ml"
    if any(path.endswith(".py") for path in lowered):
        return "python"
    return "baseline"


def pull_request_snapshot(
    pull: Mapping[str, Any],
    *,
    repository: str,
    event_head_sha: str,
    event_base_sha: str,
) -> tuple[str, bool, str, str, str, tuple[str, ...]]:
    """Validate the final-candidate state and return its race-sensitive fields."""
    repository = _require_repository(repository)
    _require_sha(event_head_sha, "event head")
    _require_sha(event_base_sha, "event base")
    if pull.get("state") != "open":
        raise ValueError("pull request is not open")
    if pull.get("draft") is not False:
        raise ValueError("draft pull request cannot enter the final lane")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise ValueError("pull request head/base metadata is missing")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if not isinstance(head_repo, Mapping) or not isinstance(base_repo, Mapping):
        raise ValueError("pull request repository metadata is missing")
    if _mapping_full_name(head_repo, "pull request head repository") != repository:
        raise ValueError("fork or detached head cannot enter the privileged final lane")
    if _mapping_full_name(base_repo, "pull request base repository") != repository:
        raise ValueError("pull request base is not the protected repository")
    if (
        base.get("ref") != DEFAULT_BRANCH
        or not isinstance(head_repo.get("id"), int)
        or head_repo.get("id") != base_repo.get("id")
    ):
        raise ValueError("pull request does not target the protected default branch")
    if head.get("sha") != event_head_sha:
        raise ValueError("event head is stale")
    if base.get("sha") != event_base_sha:
        raise ValueError("event base is stale")
    labels = pull.get("labels")
    if not isinstance(labels, list):
        raise ValueError("pull request labels are missing")
    label_names: list[str] = []
    for label in labels:
        if not isinstance(label, Mapping) or not isinstance(label.get("name"), str):
            raise ValueError("pull request label metadata is malformed")
        label_names.append(str(label["name"]))
    if "ci-final" not in label_names:
        raise ValueError("ci-final label is absent")
    return (
        "open",
        False,
        event_head_sha,
        repository,
        event_base_sha,
        tuple(sorted(label_names)),
    )


def validate_pull_request(
    pull: Mapping[str, Any],
    *,
    repository: str,
    event_head_sha: str,
    event_base_sha: str,
) -> None:
    pull_request_snapshot(
        pull,
        repository=repository,
        event_head_sha=event_head_sha,
        event_base_sha=event_base_sha,
    )


def parse_actions_details_url(
    details_url: str,
    *,
    repository: str,
    server_url: str,
) -> tuple[int, int | None]:
    """Parse one exact target-repository Actions run or job details page."""
    repository = _require_repository(repository)
    if server_url != SERVER_URL:
        raise ValueError("unexpected GitHub server URL")
    if not isinstance(details_url, str):
        raise ValueError("check details URL is missing")
    try:
        parsed = urllib.parse.urlsplit(details_url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("check details URL is malformed") from error
    expected_prefix = f"/{repository}/actions/runs/"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(expected_prefix)
    ):
        raise ValueError("check details URL is not a canonical Actions page")
    remainder = parsed.path.removeprefix(expected_prefix)
    match = re.fullmatch(r"([1-9][0-9]*)(?:/job/([1-9][0-9]*))?", remainder)
    if match is None:
        raise ValueError("check details URL has a non-canonical path")
    run_id = _require_positive_integer(match.group(1), "check run ID")
    job_id = _require_positive_integer(match.group(2), "Actions job ID") if match.group(2) is not None else None
    canonical = f"{expected_prefix}{run_id}"
    if job_id is not None:
        canonical = f"{canonical}/job/{job_id}"
    if parsed.path != canonical:
        raise ValueError("check details URL has a non-canonical path")
    return run_id, job_id


def parse_run_id(details_url: str, *, repository: str, server_url: str) -> int:
    """Return the run ID from an exact canonical Actions details page."""
    run_id, _ = parse_actions_details_url(
        details_url,
        repository=repository,
        server_url=server_url,
    )
    return run_id


def _run_identity(
    run: Mapping[str, Any],
    *,
    workflow_id: int,
    repository: str,
    head_sha: str,
    pull_request_number: int,
    action_ref: str,
) -> tuple[int, int, int]:
    workflow_id = _require_positive_integer(workflow_id, "required workflow ID")
    repository = _require_repository(repository)
    head_sha = _require_sha(head_sha, "workflow-run head")
    action_ref = _require_sha(action_ref, "action ref")
    pull_request_number = _require_positive_integer(
        pull_request_number,
        "pull request number",
    )
    run_id = _require_positive_integer(run.get("id"), "workflow run ID")
    run_number = _require_positive_integer(run.get("run_number"), "workflow run number")
    run_attempt = _require_positive_integer(
        run.get("run_attempt"),
        "workflow run attempt",
    )
    expected_workflow_url = f"{API_URL}/repos/{ACTION_REPOSITORY}/actions/workflows/{workflow_id}"
    expected_api_url = f"{API_URL}/repos/{repository}/actions/runs/{run_id}"
    expected_html_url = f"{SERVER_URL}/{repository}/actions/runs/{run_id}"
    if (
        run.get("workflow_id") != workflow_id
        or run.get("workflow_url") != expected_workflow_url
        or run.get("name") != REQUIRED_WORKFLOW_NAME
        or run.get("path") != f"{REQUIRED_WORKFLOW_PATH}@{action_ref}"
        or run.get("url") != expected_api_url
        or run.get("html_url") != expected_html_url
        or run.get("head_sha") != head_sha
        or _mapping_full_name(run.get("repository"), "workflow target repository") != repository
        or _mapping_full_name(run.get("head_repository"), "workflow head repository") != repository
    ):
        raise ValueError("required workflow run source or target identity is invalid")
    head_commit = run.get("head_commit")
    if not isinstance(head_commit, Mapping) or head_commit.get("id") != head_sha:
        raise ValueError("required workflow run head commit is invalid")
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        raise ValueError("required workflow run PR association is ambiguous")
    association = pull_requests[0]
    if not isinstance(association, Mapping) or association.get("number") != pull_request_number:
        raise ValueError("required workflow run is associated with another PR")
    associated_head = association.get("head")
    if associated_head is not None and (
        not isinstance(associated_head, Mapping) or associated_head.get("sha") != head_sha
    ):
        raise ValueError("required workflow run PR head association is invalid")
    if run.get("event") != "pull_request":
        raise ValueError("required workflow run has an unexpected event")
    return run_number, run_attempt, run_id


def validate_required_run(
    run: Mapping[str, Any],
    *,
    workflow_id: int,
    repository: str,
    head_sha: str,
    pull_request_number: int,
    action_ref: str,
) -> None:
    _run_identity(
        run,
        workflow_id=workflow_id,
        repository=repository,
        head_sha=head_sha,
        pull_request_number=pull_request_number,
        action_ref=action_ref,
    )
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("newest required workflow run did not complete successfully")


def select_latest_required_run(
    runs: Iterable[Mapping[str, Any]],
    *,
    workflow_id: int,
    repository: str,
    head_sha: str,
    pull_request_number: int,
    action_ref: str,
) -> Mapping[str, Any]:
    """Select the newest exact workflow attempt, then require that attempt to pass."""
    workflow_id = _require_positive_integer(workflow_id, "required workflow ID")
    candidates: list[tuple[tuple[int, int, int], Mapping[str, Any]]] = []
    seen: set[tuple[int, int]] = set()
    for run in runs:
        if not isinstance(run, Mapping):
            raise ValueError("workflow-run listing contains malformed metadata")
        if run.get("workflow_id") != workflow_id or run.get("head_sha") != head_sha:
            continue
        identity = _run_identity(
            run,
            workflow_id=workflow_id,
            repository=repository,
            head_sha=head_sha,
            pull_request_number=pull_request_number,
            action_ref=action_ref,
        )
        duplicate_key = (identity[2], identity[1])
        if duplicate_key in seen:
            raise ValueError("workflow-run listing contains duplicate attempt metadata")
        seen.add(duplicate_key)
        candidates.append((identity, run))
    if not candidates:
        raise ValueError("current head has no matching required workflow run")
    candidates.sort(key=lambda item: item[0], reverse=True)
    selected = candidates[0][1]
    validate_required_run(
        selected,
        workflow_id=workflow_id,
        repository=repository,
        head_sha=head_sha,
        pull_request_number=pull_request_number,
        action_ref=action_ref,
    )
    return selected


def validate_run_detail(
    summary: Mapping[str, Any],
    detail: Mapping[str, Any],
    *,
    workflow_id: int,
    repository: str,
    head_sha: str,
    pull_request_number: int,
    action_ref: str,
) -> None:
    """Require the separately fetched run detail to match the selected list record."""
    validate_required_run(
        detail,
        workflow_id=workflow_id,
        repository=repository,
        head_sha=head_sha,
        pull_request_number=pull_request_number,
        action_ref=action_ref,
    )
    fields = (
        "id",
        "workflow_id",
        "run_number",
        "run_attempt",
        "head_sha",
        "status",
        "conclusion",
        "path",
        "workflow_url",
    )
    if any(summary.get(field) != detail.get(field) for field in fields):
        raise ValueError("required workflow run changed between API reads")


def _validated_job_attempt(
    job: Mapping[str, Any],
    check: Mapping[str, Any],
    *,
    job_id: int,
    run_id: int,
    head_sha: str,
    repository: str,
) -> int:
    repository = _require_repository(repository)
    head_sha = _require_sha(head_sha, "job head")
    job_id = _require_positive_integer(job_id, "Actions job ID")
    run_id = _require_positive_integer(run_id, "workflow run ID")
    check_id = _require_positive_integer(check.get("id"), "check-run ID")
    run_attempt = _require_positive_integer(
        job.get("run_attempt"),
        "Actions job run attempt",
    )
    expected_run_url = f"{API_URL}/repos/{repository}/actions/runs/{run_id}"
    expected_job_url = f"{API_URL}/repos/{repository}/actions/jobs/{job_id}"
    expected_job_html = f"{SERVER_URL}/{repository}/actions/runs/{run_id}/job/{job_id}"
    expected_check_url = f"{API_URL}/repos/{repository}/check-runs/{check_id}"
    if (
        job.get("id") != job_id
        or job.get("run_id") != run_id
        or job.get("run_url") != expected_run_url
        or job.get("head_sha") != head_sha
        or job.get("name") != check.get("name")
        or job.get("check_run_url") != expected_check_url
        or job.get("url") != expected_job_url
        or job.get("html_url") != expected_job_html
    ):
        raise ValueError("Actions job is not bound to the selected run and check")
    return run_attempt


def validate_job_binding(
    job: Mapping[str, Any],
    check: Mapping[str, Any],
    *,
    job_id: int,
    run_id: int,
    run_attempt: int,
    head_sha: str,
    repository: str,
) -> None:
    """Require the job page to identify the selected successful run attempt/check."""
    expected_attempt = _require_positive_integer(
        run_attempt,
        "selected workflow run attempt",
    )
    actual_attempt = _validated_job_attempt(
        job,
        check,
        job_id=job_id,
        run_id=run_id,
        head_sha=head_sha,
        repository=repository,
    )
    if (
        actual_attempt != expected_attempt
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
    ):
        raise ValueError("Actions job/check is not a successful selected run attempt")


def select_required_check(
    checks: Iterable[Mapping[str, Any]],
    required_context: str,
    head_sha: str,
    *,
    run_id: int,
    run_attempt: int,
    repository: str,
    server_url: str,
    token: str,
    api_url: str,
) -> Mapping[str, Any]:
    """Resolve one unambiguous current-attempt check tied to the selected run."""
    if required_context != REQUIRED_CONTEXT:
        raise ValueError("unexpected required fast context")
    head_sha = _require_sha(head_sha, "check head")
    run_id = _require_positive_integer(run_id, "workflow run ID")
    run_attempt = _require_positive_integer(
        run_attempt,
        "selected workflow run attempt",
    )
    named: list[Mapping[str, Any]] = []
    for check in checks:
        if not isinstance(check, Mapping):
            raise ValueError("check-run listing contains malformed metadata")
        if check.get("name") == required_context:
            named.append(check)
    if not named:
        raise ValueError("current head has no required fast check")

    run_page_checks: list[Mapping[str, Any]] = []
    selected_job_checks: list[tuple[Mapping[str, Any], Mapping[str, Any], int]] = []
    for check in named:
        app = check.get("app")
        if (
            check.get("head_sha") != head_sha
            or not isinstance(app, Mapping)
            or app.get("slug") != "github-actions"
            or app.get("id") != GITHUB_ACTIONS_APP_ID
        ):
            raise ValueError("required fast check publisher or head is invalid")
        _require_positive_integer(check.get("id"), "check-run ID")
        details_url = check.get("details_url")
        if not isinstance(details_url, str):
            raise ValueError("required fast check details URL is missing")
        details_run_id, job_id = parse_actions_details_url(
            details_url,
            repository=repository,
            server_url=server_url,
        )
        if details_run_id != run_id:
            raise ValueError("required fast check points to another workflow run")
        if job_id is None:
            run_page_checks.append(check)
            continue
        job = api_request(
            "GET",
            f"/repos/{repository}/actions/jobs/{job_id}",
            token=token,
            api_url=api_url,
        )
        if not isinstance(job, Mapping):
            raise RuntimeError("GitHub returned malformed Actions job metadata")
        actual_attempt = _validated_job_attempt(
            job,
            check,
            job_id=job_id,
            run_id=run_id,
            head_sha=head_sha,
            repository=repository,
        )
        if actual_attempt == run_attempt:
            selected_job_checks.append((check, job, job_id))

    if selected_job_checks:
        if len(selected_job_checks) != 1 or run_page_checks:
            raise ValueError("current attempt has ambiguous required fast checks")
        check, job, job_id = selected_job_checks[0]
        validate_job_binding(
            job,
            check,
            job_id=job_id,
            run_id=run_id,
            run_attempt=run_attempt,
            head_sha=head_sha,
            repository=repository,
        )
        return check
    if len(named) == 1 and len(run_page_checks) == 1:
        check = run_page_checks[0]
        if check.get("status") == "completed" and check.get("conclusion") == "success":
            return check
    raise ValueError("current attempt has no unambiguous successful required fast check")


def api_request(
    method: str,
    path: str,
    *,
    token: str,
    api_url: str,
    payload: Mapping[str, Any] | None = None,
) -> Any:
    if api_url != API_URL:
        raise ValueError("unexpected GitHub API URL")
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or any(character in path for character in "\r\n")
    ):
        raise ValueError("GitHub API path is invalid")
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "koios-ci-platform",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with API_OPENER.open(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise RuntimeError("GitHub API redirect refused")
            status = getattr(response, "status", None)
            if isinstance(status, bool) or not isinstance(status, int):
                raise RuntimeError("GitHub API returned a malformed HTTP status")
            if status < 200 or status >= 300:
                raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {status}")
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise RuntimeError("GitHub API redirect refused") from error
        raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"GitHub API {method} {path} failed") from error


def paginated_items(path: str, key: str | None, *, token: str, api_url: str) -> list[Any]:
    values: list[Any] = []
    separator = "&" if "?" in path else "?"
    expected_total: int | None = None
    for page in range(1, MAX_API_PAGES + 1):
        payload = api_request(
            "GET",
            f"{path}{separator}per_page={PAGE_SIZE}&page={page}",
            token=token,
            api_url=api_url,
        )
        if key is None:
            items = payload
        else:
            if not isinstance(payload, Mapping) or key not in payload:
                raise RuntimeError("GitHub API returned a malformed paginated response")
            items = payload[key]
            total = payload.get("total_count")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise RuntimeError("GitHub API returned a malformed pagination total")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise RuntimeError("GitHub API pagination total changed between pages")
        if not isinstance(items, list):
            raise RuntimeError("GitHub API returned a malformed paginated response")
        values.extend(items)
        if expected_total is not None and len(values) > expected_total:
            raise RuntimeError("GitHub API pagination exceeded its declared total")
        complete = len(items) < PAGE_SIZE or (expected_total is not None and len(values) == expected_total)
        if complete:
            if expected_total is not None and len(values) != expected_total:
                raise RuntimeError("GitHub API pagination ended before its declared total")
            return values
    raise RuntimeError("GitHub API pagination exceeded the bounded page limit")


def _write_outputs(values: Sequence[tuple[str, str]]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise ValueError("GitHub output channel is unavailable")
    with open(output_path, "a", encoding="utf-8") as output:
        for name, value in values:
            output.write(f"{name}={value}\n")


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    repository = _require_repository(os.environ.get("GITHUB_REPOSITORY", ""))
    api_url = os.environ.get("GITHUB_API_URL", "")
    server_url = os.environ.get("GITHUB_SERVER_URL", "")
    action_repository = os.environ.get("TRUSTED_ACTION_REPOSITORY", "")
    action_ref = os.environ.get("TRUSTED_ACTION_REF", "")
    if not token or any(character in token for character in "\r\n"):
        raise ValueError("trusted GitHub token is unavailable")
    if api_url != API_URL:
        raise ValueError("unexpected GitHub API URL")
    if server_url != SERVER_URL:
        raise ValueError("unexpected GitHub server URL")
    if action_repository != ACTION_REPOSITORY:
        raise ValueError("preflight action repository identity is invalid")
    action_ref = _require_sha(action_ref, "github.action_ref")

    number = _require_positive_integer(
        os.environ.get("INPUT_PULL_REQUEST_NUMBER", ""),
        "pull request number",
    )
    workflow_id = _require_positive_integer(
        os.environ.get("INPUT_REQUIRED_FAST_WORKFLOW_ID", ""),
        "required workflow ID",
    )
    event_head = _require_sha(
        os.environ.get("INPUT_EVENT_HEAD_SHA", ""),
        "event head",
    )
    event_base = _require_sha(
        os.environ.get("INPUT_EVENT_BASE_SHA", ""),
        "event base",
    )
    context = os.environ.get("INPUT_REQUIRED_FAST_CONTEXT", "")
    if context != REQUIRED_CONTEXT:
        raise ValueError("unexpected required fast context")

    pull_path = f"/repos/{repository}/pulls/{number}"
    pull = api_request("GET", pull_path, token=token, api_url=api_url)
    if not isinstance(pull, Mapping) or pull.get("number") not in {None, number}:
        raise RuntimeError("GitHub returned malformed pull request metadata")
    initial_snapshot = pull_request_snapshot(
        pull,
        repository=repository,
        event_head_sha=event_head,
        event_base_sha=event_base,
    )

    encoded_head = urllib.parse.quote(event_head, safe="")
    runs = paginated_items(
        f"/repos/{repository}/actions/runs?head_sha={encoded_head}",
        "workflow_runs",
        token=token,
        api_url=api_url,
    )
    selected_run = select_latest_required_run(
        runs,
        workflow_id=workflow_id,
        repository=repository,
        head_sha=event_head,
        pull_request_number=number,
        action_ref=action_ref,
    )
    run_id = _require_positive_integer(selected_run.get("id"), "workflow run ID")
    run_detail = api_request(
        "GET",
        f"/repos/{repository}/actions/runs/{run_id}",
        token=token,
        api_url=api_url,
    )
    if not isinstance(run_detail, Mapping):
        raise RuntimeError("GitHub returned malformed workflow-run metadata")
    validate_run_detail(
        selected_run,
        run_detail,
        workflow_id=workflow_id,
        repository=repository,
        head_sha=event_head,
        pull_request_number=number,
        action_ref=action_ref,
    )

    checks = paginated_items(
        f"/repos/{repository}/commits/{event_head}/check-runs?filter=all",
        "check_runs",
        token=token,
        api_url=api_url,
    )
    select_required_check(
        checks,
        context,
        event_head,
        run_id=run_id,
        run_attempt=_require_positive_integer(
            selected_run.get("run_attempt"),
            "workflow run attempt",
        ),
        repository=repository,
        server_url=server_url,
        token=token,
        api_url=api_url,
    )

    files_payload = paginated_items(
        f"/repos/{repository}/pulls/{number}/files",
        None,
        token=token,
        api_url=api_url,
    )
    if any(not isinstance(item, Mapping) for item in files_payload):
        raise RuntimeError("GitHub returned malformed changed-file metadata")
    paths = sorted(
        {str(item["filename"]) for item in files_payload if isinstance(item.get("filename"), str) and item["filename"]}
    )
    if not paths or len(paths) != len(files_payload):
        raise ValueError("final candidate has missing or duplicate changed-file metadata")
    profile = classify_profile(paths)
    digest = canonical_changed_files_digest(paths)

    refreshed = api_request("GET", pull_path, token=token, api_url=api_url)
    if not isinstance(refreshed, Mapping) or refreshed.get("number") not in {
        None,
        number,
    }:
        raise RuntimeError("GitHub returned malformed refreshed pull request metadata")
    refreshed_snapshot = pull_request_snapshot(
        refreshed,
        repository=repository,
        event_head_sha=event_head,
        event_base_sha=event_base,
    )
    if refreshed_snapshot != initial_snapshot:
        raise ValueError("pull request state changed during final preflight")

    _write_outputs(
        (
            ("ready", "true"),
            ("profile", profile),
            ("head_sha", event_head),
            ("base_sha", event_base),
            ("changed_files_digest", digest),
        )
    )


if __name__ == "__main__":
    main()
