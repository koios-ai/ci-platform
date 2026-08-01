"""Trusted, evidence-bound publisher for one deterministic final context."""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
API_URL = "https://api.github.com"
SERVER_URL = "https://github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
DEFAULT_BRANCH = "main"
GITHUB_ACTIONS_APP = {"id": 15368, "slug": "github-actions"}
DEEPSOURCE_CHECK_APP = {"id": 16372, "slug": "deepsource-io"}
DEEPSOURCE_ANALYSIS_CHECK = "DeepSource analysis"
DEEPSOURCE_STATUS_CREATOR = {
    "id": 42547082,
    "login": "deepsource-io[bot]",
    "type": "Bot",
}
DEEPSOURCE_CONFIG_PATH = ".deepsource.toml"
DEEPSOURCE_CONFIG_LIMIT = 64 * 1024
DEEPSOURCE_POLL_SECONDS = 15
DEEPSOURCE_TIMEOUT_SECONDS = 300
WORKFLOW_PATH = ".github/workflows/final-required.yml"
REUSABLE_WORKFLOW_PATH = "koios-ai/ci-platform/.github/workflows/reusable-final.yml"
PUBLISHERS = {
    (WORKFLOW_PATH, "publish-security"): "Security / required",
    (WORKFLOW_PATH, "publish-coverage"): "Coverage / required",
}
FINAL_RESULTS = {"success", "failure", "cancelled", "skipped"}


class AmbiguousWriteError(RuntimeError):
    """The server may have accepted a write whose response was not received."""


class ApiNotFoundError(RuntimeError):
    """The exact GitHub object does not exist."""


class DeepSourcePolicy:
    """Trusted base-branch policy derived from the checked-in vendor config."""

    __slots__ = (
        "config_blob_sha",
        "dependency_contexts",
        "test_coverage_enabled",
    )

    def __init__(
        self,
        *,
        config_blob_sha: str,
        test_coverage_enabled: bool,
        dependency_contexts: frozenset[str],
    ) -> None:
        self.config_blob_sha = config_blob_sha
        self.test_coverage_enabled = test_coverage_enabled
        self.dependency_contexts = dependency_contexts


class DeepSourceEvaluation:
    """Bounded native-provider result folded into the security context."""

    __slots__ = ("details", "evidence_digest", "state")

    def __init__(
        self,
        *,
        state: str,
        evidence_digest: str,
        details: tuple[str, ...] = (),
    ) -> None:
        self.state = state
        self.evidence_digest = evidence_digest
        self.details = details

    @property
    def passing(self) -> bool:
        return self.state in {"passed", "not-configured"}


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


def resolve_context(workflow_path: str, job_id: str) -> str:
    try:
        return PUBLISHERS[(workflow_path, job_id)]
    except KeyError as error:
        raise ValueError("runtime is not an approved deterministic publisher") from error


def parse_deepsource_policy(raw: bytes, config_blob_sha: str) -> DeepSourcePolicy:
    """Parse a bounded base-branch config without executing consumer code."""
    if not FULL_SHA.fullmatch(config_blob_sha):
        raise ValueError("DeepSource config blob SHA is malformed")
    if not raw or len(raw) > DEEPSOURCE_CONFIG_LIMIT:
        raise ValueError("DeepSource config is empty or exceeds the size limit")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("DeepSource config is not valid UTF-8 TOML") from error
    if document.get("version") != 1:
        raise ValueError("DeepSource config version must be exactly 1")
    analyzers = document.get("analyzers")
    if not isinstance(analyzers, list) or not analyzers:
        raise ValueError("DeepSource config has no analyzers")

    test_coverage_enabled = False
    dependencies: set[str] = set()
    for index, analyzer in enumerate(analyzers):
        if not isinstance(analyzer, Mapping):
            raise ValueError(f"DeepSource analyzer {index} is malformed")
        name = analyzer.get("name")
        enabled = analyzer.get("enabled", True)
        if not isinstance(name, str) or not name or not isinstance(enabled, bool):
            raise ValueError(f"DeepSource analyzer {index} has an invalid name or enabled flag")
        if not enabled:
            continue
        if name == "test-coverage":
            test_coverage_enabled = True
        if name != "python":
            continue
        meta = analyzer.get("meta", {})
        if not isinstance(meta, Mapping):
            raise ValueError("DeepSource Python analyzer metadata is malformed")
        paths = meta.get("dependency_file_paths", [])
        if not isinstance(paths, list):
            raise ValueError("DeepSource dependency_file_paths must be a list")
        for value in paths:
            if not isinstance(value, str) or not value or "\\" in value:
                raise ValueError("DeepSource dependency path is malformed")
            path = pathlib.PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
                raise ValueError("DeepSource dependency path escapes the repository")
            dependencies.add(f"DeepSource: {path.name}")
    return DeepSourcePolicy(
        config_blob_sha=config_blob_sha,
        test_coverage_enabled=test_coverage_enabled,
        dependency_contexts=frozenset(dependencies),
    )


def _deepsource_evaluation(
    state: str,
    *,
    policy: DeepSourcePolicy | None,
    statuses: Sequence[Mapping[str, Any]] = (),
    checks: Sequence[Mapping[str, Any]] = (),
    details: Sequence[str] = (),
) -> DeepSourceEvaluation:
    allowed_states = {
        "failed",
        "not-configured",
        "not-evaluated",
        "passed",
        "pending",
        "timed-out",
        "unavailable",
    }
    if state not in allowed_states:
        raise ValueError("DeepSource evaluation state is invalid")
    payload = {
        "state": state,
        "config_blob_sha": policy.config_blob_sha if policy else "not-configured",
        "test_coverage_enabled": policy.test_coverage_enabled if policy else False,
        "dependency_contexts": sorted(policy.dependency_contexts) if policy else [],
        "statuses": [
            {
                "id": item.get("id"),
                "context": item.get("context"),
                "state": item.get("state"),
                "target_url_digest": hashlib.sha256(str(item.get("target_url") or "").encode("utf-8")).hexdigest(),
            }
            for item in sorted(
                statuses,
                key=lambda item: (
                    str(item.get("context") or ""),
                    int(item.get("id", 0)),
                ),
            )
        ],
        "checks": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
            }
            for item in sorted(
                checks,
                key=lambda item: (
                    str(item.get("name") or ""),
                    int(item.get("id", 0)),
                ),
            )
        ],
        "details": sorted(str(detail) for detail in details),
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return DeepSourceEvaluation(
        state=state,
        evidence_digest=digest,
        details=tuple(str(detail) for detail in details),
    )


def _is_ignored_deepsource_status(
    policy: DeepSourcePolicy,
    context: str,
    state: str,
) -> bool:
    if context == "DeepSource: Test coverage" and not policy.test_coverage_enabled:
        return True
    if context == "DeepSource: AI Review" and state not in {"failure", "error"}:
        return True
    if context.startswith("DeepSource: requirements"):
        return context not in policy.dependency_contexts
    return False


def _valid_deepsource_target(repository: str, target_url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(target_url)
        port = parsed.port
    except ValueError:
        return False
    prefix = f"/gh/{repository}/run/"
    return (
        parsed.scheme == "https"
        and parsed.hostname == "app.deepsource.com"
        and parsed.username is None
        and parsed.password is None
        and port is None
        and parsed.path.startswith(prefix)
        and len(parsed.path) > len(prefix)
        and not parsed.query
        and not parsed.fragment
    )


def evaluate_deepsource_signals(
    policy: DeepSourcePolicy,
    statuses: Sequence[Mapping[str, Any]],
    check_runs: Sequence[Mapping[str, Any]],
    *,
    repository: str,
    head_sha: str,
) -> DeepSourceEvaluation:
    """Require newest exact-provider statuses and configured dependency contexts."""
    if not FULL_SHA.fullmatch(head_sha):
        raise ValueError("DeepSource target head SHA is malformed")

    newest: dict[str, Mapping[str, Any]] = {}
    malformed_details: list[str] = []
    for item in statuses:
        context = item.get("context")
        if not isinstance(context, str) or not context.lower().startswith("deepsource:"):
            continue
        identifier = item.get("id")
        state = item.get("state")
        if (
            isinstance(identifier, bool)
            or not isinstance(identifier, int)
            or identifier < 1
            or not isinstance(state, str)
            or len(context) > 256
        ):
            malformed_details.append("malformed native status metadata")
            continue
        prior = newest.get(context)
        prior_id = prior.get("id") if isinstance(prior, Mapping) else None
        if not isinstance(prior_id, int) or identifier > prior_id:
            newest[context] = item
    if malformed_details:
        return _deepsource_evaluation(
            "failed",
            policy=policy,
            details=malformed_details,
        )

    selected: list[Mapping[str, Any]] = []
    identity_failures: list[str] = []
    for context, item in sorted(newest.items()):
        state = str(item.get("state") or "").lower()
        if _is_ignored_deepsource_status(policy, context, state):
            continue
        creator = item.get("creator")
        target_url = item.get("target_url")
        if (
            not isinstance(creator, Mapping)
            or any(creator.get(key) != value for key, value in DEEPSOURCE_STATUS_CREATOR.items())
            or not isinstance(target_url, str)
            or not _valid_deepsource_target(repository, target_url)
        ):
            identity_failures.append(f"{context}: untrusted provider identity")
            continue
        if state not in {"error", "failure", "pending", "success"}:
            identity_failures.append(f"{context}: invalid provider state")
            continue
        selected.append(item)
    if identity_failures:
        return _deepsource_evaluation(
            "failed",
            policy=policy,
            statuses=selected,
            details=identity_failures,
        )

    selected_by_context = {str(item.get("context")): item for item in selected}
    missing_dependencies = sorted(policy.dependency_contexts - set(selected_by_context))

    analysis_checks: list[Mapping[str, Any]] = []
    check_failures: list[str] = []
    for item in check_runs:
        app = item.get("app")
        if (
            not isinstance(app, Mapping)
            or app.get("id") != DEEPSOURCE_CHECK_APP["id"]
            or app.get("slug") != DEEPSOURCE_CHECK_APP["slug"]
            or item.get("name") != DEEPSOURCE_ANALYSIS_CHECK
        ):
            continue
        identifier = item.get("id")
        status = item.get("status")
        if (
            isinstance(identifier, bool)
            or not isinstance(identifier, int)
            or identifier < 1
            or item.get("head_sha") != head_sha
            or status not in {"completed", "in_progress", "queued", "waiting", "pending"}
        ):
            check_failures.append("malformed DeepSource analysis check metadata")
            continue
        analysis_checks.append(item)

    analysis_by_id: dict[int, Mapping[str, Any]] = {}
    for item in analysis_checks:
        identifier = int(item["id"])
        if identifier in analysis_by_id:
            check_failures.append("duplicate DeepSource analysis check ID")
        analysis_by_id[identifier] = item
    newest_analysis = analysis_by_id[max(analysis_by_id)] if analysis_by_id else None
    selected_checks = [newest_analysis] if newest_analysis is not None else []
    check_pending: list[str] = []
    if newest_analysis is None:
        check_pending.append("missing DeepSource analysis")
    elif newest_analysis.get("status") != "completed":
        check_pending.append(DEEPSOURCE_ANALYSIS_CHECK)
    elif newest_analysis.get("conclusion") != "success":
        check_failures.append(
            f"{DEEPSOURCE_ANALYSIS_CHECK}: {newest_analysis.get('conclusion') or 'missing conclusion'}"
        )

    status_failures = [
        f"{item.get('context')}: {item.get('state')}"
        for item in selected
        if str(item.get("state") or "").lower() in {"failure", "error"}
    ]
    status_pending = [
        str(item.get("context")) for item in selected if str(item.get("state") or "").lower() == "pending"
    ]
    if status_failures or check_failures:
        return _deepsource_evaluation(
            "failed",
            policy=policy,
            statuses=selected,
            checks=selected_checks,
            details=(*status_failures, *check_failures),
        )
    if not selected or missing_dependencies or status_pending or check_pending:
        details = [
            *(["no non-ignored native DeepSource status"] if not selected else []),
            *[f"missing {context}" for context in missing_dependencies],
            *[f"pending {context}" for context in status_pending],
            *[f"pending check {name}" for name in check_pending],
        ]
        return _deepsource_evaluation(
            "pending",
            policy=policy,
            statuses=selected,
            checks=selected_checks,
            details=details,
        )
    return _deepsource_evaluation(
        "passed",
        policy=policy,
        statuses=selected,
        checks=selected_checks,
    )


def derive_conclusion(
    context: str,
    *,
    upstream_result: str,
    gate_passed: str,
    coverage_upload_result: str,
    evidence_digest: str,
) -> str:
    if context not in set(PUBLISHERS.values()):
        raise ValueError("publisher context is not allowed")
    if upstream_result not in FINAL_RESULTS:
        raise ValueError("upstream result is malformed")
    if coverage_upload_result not in FINAL_RESULTS | {"not-applicable"}:
        raise ValueError("coverage upload result is malformed")
    if upstream_result == "cancelled" or coverage_upload_result == "cancelled":
        return "cancelled"
    successful = (
        upstream_result == "success"
        and gate_passed == "true"
        and (
            (context == "Security / required" and coverage_upload_result == "not-applicable")
            or (context == "Coverage / required" and coverage_upload_result == "success")
        )
    )
    if successful:
        if not DIGEST.fullmatch(evidence_digest):
            raise ValueError("successful publication lacks a bounded evidence digest")
        return "success"
    return "failure"


def validate_candidate(pull: Mapping[str, Any], repository: str, head_sha: str) -> None:
    if not FULL_SHA.fullmatch(head_sha):
        raise ValueError("expected head is not a full lowercase SHA")
    if pull.get("state") != "open" or pull.get("draft") is not False:
        raise ValueError("pull request is closed or draft")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise ValueError("pull request head/base metadata is missing")
    if base.get("ref") != DEFAULT_BRANCH:
        raise ValueError("pull request does not target the protected default branch")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if (
        head.get("sha") != head_sha
        or not isinstance(head_repo, Mapping)
        or head_repo.get("full_name") != repository
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != repository
        or not isinstance(head_repo.get("id"), int)
        or head_repo.get("id") != base_repo.get("id")
    ):
        raise ValueError("pull request head changed or is not same-repository")
    labels = pull.get("labels")
    if not isinstance(labels, list) or "ci-final" not in {
        label.get("name") for label in labels if isinstance(label, Mapping)
    }:
        raise ValueError("ci-final label is absent")


def validate_runtime(
    runtime: Mapping[str, str],
    pull: Mapping[str, Any],
    repository: str,
    context: str,
) -> None:
    head = pull["head"]
    base = pull["base"]
    assert isinstance(head, Mapping) and isinstance(base, Mapping)
    base_repo = base["repo"]
    assert isinstance(base_repo, Mapping)
    base_sha = base.get("sha")
    if (
        runtime.get("api_url") != API_URL
        or runtime.get("server_url") != SERVER_URL
        or runtime.get("event_name") != "pull_request_target"
        or runtime.get("action_repository") != ACTION_REPOSITORY
        or not FULL_SHA.fullmatch(runtime.get("action_ref", ""))
        or runtime.get("workflow_repository") != repository
        or runtime.get("workflow_file_path") != WORKFLOW_PATH
        or runtime.get("workflow_sha") != base_sha
        or runtime.get("workflow_ref") != f"{repository}/{WORKFLOW_PATH}@refs/heads/{DEFAULT_BRANCH}"
        or resolve_context(WORKFLOW_PATH, runtime.get("job_id", "")) != context
        or str(base_repo.get("id")) != runtime.get("repository_id")
    ):
        raise ValueError("publisher runtime workflow or action identity is invalid")
    for field in ("job_check_run_id", "run_id", "run_attempt", "repository_id"):
        value = runtime.get(field, "")
        if not value.isdecimal() or int(value) < 1:
            raise ValueError(f"publisher runtime identifier is invalid: {field}")


def canonical_external_id(identity: Mapping[str, str]) -> str:
    required = {
        "repository",
        "repository_id",
        "pull_request_number",
        "head_sha",
        "context",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "evidence_digest",
        "deepsource_evidence_digest",
        "action_ref",
        "job_id",
        "job_check_run_id",
    }
    if set(identity) != required:
        raise ValueError("external identity fields are incomplete")
    canonical = json.dumps(
        {key: identity[key] for key in sorted(identity)},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    suffix = identity["context"].lower().replace(" / ", "-")
    return f"ci-platform-final:v1:{hashlib.sha256(canonical).hexdigest()}:{suffix}"


def build_check_payload(identity: Mapping[str, str], conclusion: str) -> dict[str, Any]:
    if conclusion not in {"success", "failure", "cancelled"}:
        raise ValueError("unsupported final check conclusion")
    if not FULL_SHA.fullmatch(identity.get("head_sha", "")):
        raise ValueError("check head is malformed")
    if identity.get("context") not in set(PUBLISHERS.values()):
        raise ValueError("check context is not approved")
    for field in ("repository_id", "pull_request_number", "run_id", "run_attempt"):
        if not identity.get(field, "").isdecimal():
            raise ValueError(f"check identity field is malformed: {field}")
    for field in ("workflow_sha", "action_ref"):
        if not FULL_SHA.fullmatch(identity.get(field, "")):
            raise ValueError(f"check identity SHA is malformed: {field}")
    digest = identity.get("evidence_digest", "")
    if conclusion == "success" and not DIGEST.fullmatch(digest):
        raise ValueError("success check has no evidence digest")
    if conclusion != "success" and digest and not DIGEST.fullmatch(digest):
        raise ValueError("failure evidence digest is malformed")
    deepsource_digest = identity.get("deepsource_evidence_digest", "")
    if identity["context"] == "Security / required":
        if not DIGEST.fullmatch(deepsource_digest):
            raise ValueError("security check has no DeepSource evidence digest")
    elif deepsource_digest != "not-applicable":
        raise ValueError("non-security check carries DeepSource evidence")
    completed = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    repository = identity["repository"]
    run_id = identity["run_id"]
    attempt = identity["run_attempt"]
    context = identity["context"]
    evidence = digest if digest else "unavailable"
    provider_summary = (
        f" DeepSource evidence digest: `{deepsource_digest}`." if context == "Security / required" else ""
    )
    return {
        "name": context,
        "head_sha": identity["head_sha"],
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": completed,
        "details_url": (f"{SERVER_URL}/{repository}/actions/runs/{run_id}/attempts/{attempt}"),
        "external_id": canonical_external_id(identity),
        "output": {
            "title": f"{context}: {conclusion}",
            "summary": (
                "Trusted default-branch controller result. "
                f"Evidence digest: `{evidence}`. "
                f"{provider_summary}"
                f"Workflow SHA: `{identity['workflow_sha']}`. "
                f"Platform SHA: `{identity['action_ref']}`."
            ),
        },
    }


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
            "User-Agent": "koios-ci-platform",
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
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if ambiguous_write and method in {"POST", "PATCH"} and (error.code in {408, 425, 429} or error.code >= 500):
            raise AmbiguousWriteError("GitHub check write result is ambiguous") from error
        if 300 <= error.code < 400:
            raise RuntimeError("GitHub API redirect refused") from error
        if method == "GET" and error.code == 404:
            raise ApiNotFoundError(f"GitHub API object not found: {path}") from error
        raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
    except (TimeoutError, urllib.error.URLError) as error:
        if ambiguous_write and method in {"POST", "PATCH"}:
            raise AmbiguousWriteError("GitHub check write result is ambiguous") from error
        raise RuntimeError(f"GitHub API {method} request failed") from error


def fetch_base_deepsource_policy(
    repository: str,
    base_sha: str,
    *,
    token: str,
) -> DeepSourcePolicy | None:
    """Load only the exact protected-base config through repository metadata."""
    if not FULL_SHA.fullmatch(base_sha):
        raise ValueError("DeepSource base SHA is malformed")
    try:
        payload = api_request(
            "GET",
            (f"/repos/{repository}/contents/{DEEPSOURCE_CONFIG_PATH}?ref={base_sha}"),
            token=token,
        )
    except ApiNotFoundError:
        return None
    if not isinstance(payload, Mapping):
        raise RuntimeError("GitHub returned malformed DeepSource config metadata")
    content = payload.get("content")
    size = payload.get("size")
    blob_sha = payload.get("sha")
    if (
        payload.get("type") != "file"
        or payload.get("path") != DEEPSOURCE_CONFIG_PATH
        or payload.get("encoding") != "base64"
        or not isinstance(content, str)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= DEEPSOURCE_CONFIG_LIMIT
        or not isinstance(blob_sha, str)
        or not FULL_SHA.fullmatch(blob_sha)
    ):
        raise RuntimeError("DeepSource config metadata is invalid or oversized")
    try:
        raw = base64.b64decode("".join(content.splitlines()), validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError("DeepSource config content is not valid base64") from error
    if len(raw) != size:
        raise RuntimeError("DeepSource config size does not match its metadata")
    return parse_deepsource_policy(raw, blob_sha)


def paginated_commit_statuses(
    repository: str,
    head_sha: str,
    *,
    token: str,
) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (f"/repos/{repository}/commits/{head_sha}/statuses?per_page=100&page={page}"),
            token=token,
        )
        if not isinstance(payload, list) or not all(isinstance(item, Mapping) for item in payload):
            raise RuntimeError("GitHub returned malformed commit-status pagination")
        values.extend(payload)
        if len(payload) < 100:
            return values
    raise RuntimeError("commit-status pagination exceeded the bounded page limit")


def paginated_provider_check_runs(
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
            raise RuntimeError("GitHub returned malformed provider check-run pagination")
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or (expected_total is not None and total != expected_total)
        ):
            raise RuntimeError("GitHub returned malformed provider check-run total")
        expected_total = total
        values.extend(items)
        if len(items) < 100:
            if len(values) != expected_total:
                raise RuntimeError("GitHub provider check-run pagination was truncated")
            return values
    raise RuntimeError("provider check-run pagination exceeded the bounded page limit")


def poll_deepsource(
    repository: str,
    head_sha: str,
    base_sha: str,
    *,
    token: str,
    timeout_seconds: int = DEEPSOURCE_TIMEOUT_SECONDS,
    poll_seconds: int = DEEPSOURCE_POLL_SECONDS,
) -> DeepSourceEvaluation:
    """Poll exact-head native signals; missing, timeout, and API outage fail closed."""
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 0 <= timeout_seconds <= DEEPSOURCE_TIMEOUT_SECONDS
        or isinstance(poll_seconds, bool)
        or not isinstance(poll_seconds, int)
        or not 0 <= poll_seconds <= 60
    ):
        raise ValueError("DeepSource polling bounds are invalid")
    deadline = time.monotonic() + timeout_seconds
    last = _deepsource_evaluation(
        "unavailable",
        policy=None,
        details=("DeepSource evaluation has not started",),
    )
    while True:
        try:
            policy = fetch_base_deepsource_policy(
                repository,
                base_sha,
                token=token,
            )
            if policy is None:
                return _deepsource_evaluation(
                    "not-configured",
                    policy=None,
                )
            last = evaluate_deepsource_signals(
                policy,
                paginated_commit_statuses(
                    repository,
                    head_sha,
                    token=token,
                ),
                paginated_provider_check_runs(
                    repository,
                    head_sha,
                    token=token,
                ),
                repository=repository,
                head_sha=head_sha,
            )
        except ValueError as error:
            return _deepsource_evaluation(
                "failed",
                policy=None,
                details=(str(error),),
            )
        except RuntimeError as error:
            last = _deepsource_evaluation(
                "unavailable",
                policy=None,
                details=(str(error),),
            )
        if last.passing or last.state == "failed":
            return last
        if time.monotonic() >= deadline:
            return _deepsource_evaluation(
                "timed-out",
                policy=None,
                details=(f"last state: {last.state}", *last.details),
            )
        time.sleep(poll_seconds)


def paginated_check_runs(
    repository: str,
    head_sha: str,
    context: str,
    *,
    token: str,
) -> list[Mapping[str, Any]]:
    encoded = urllib.parse.quote(context, safe="")
    values: list[Mapping[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (
                f"/repos/{repository}/commits/{head_sha}/check-runs"
                f"?check_name={encoded}&filter=all&per_page=100&page={page}"
            ),
            token=token,
        )
        items = payload.get("check_runs", []) if isinstance(payload, Mapping) else None
        if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
            raise RuntimeError("GitHub returned malformed check-run pagination")
        total = payload.get("total_count") if isinstance(payload, Mapping) else None
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


def _matching_owned_check(checks: list[Mapping[str, Any]], external_id: str, context: str) -> Mapping[str, Any] | None:
    matching = [
        check
        for check in checks
        if check.get("external_id") == external_id
        and check.get("name") == context
        and isinstance(check.get("app"), Mapping)
        and check["app"].get("id") == GITHUB_ACTIONS_APP["id"]
        and check["app"].get("slug") == GITHUB_ACTIONS_APP["slug"]
        and isinstance(check.get("id"), int)
    ]
    if len(matching) > 1:
        raise RuntimeError("multiple owned check runs share one external identity")
    return matching[0] if matching else None


def validate_written_check(
    check: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> None:
    app = check.get("app")
    for field in (
        "name",
        "head_sha",
        "status",
        "conclusion",
        "details_url",
        "external_id",
        "completed_at",
    ):
        if check.get(field) != payload.get(field):
            raise RuntimeError(f"published check readback mismatch: {field}")
    if (
        not isinstance(app, Mapping)
        or app.get("id") != GITHUB_ACTIONS_APP["id"]
        or app.get("slug") != GITHUB_ACTIONS_APP["slug"]
    ):
        raise RuntimeError("published check is not owned by GitHub Actions")
    actual_output = check.get("output")
    expected_output = payload.get("output")
    if not isinstance(actual_output, Mapping) or not isinstance(expected_output, Mapping):
        raise RuntimeError("published check output is missing")
    for field in ("title", "summary"):
        if actual_output.get(field) != expected_output.get(field):
            raise RuntimeError(f"published check output mismatch: {field}")


def _fetch_pull(
    repository: str,
    number: int,
    head_sha: str,
    *,
    token: str,
) -> Mapping[str, Any]:
    pull = api_request(
        "GET",
        f"/repos/{repository}/pulls/{number}",
        token=token,
    )
    if not isinstance(pull, Mapping):
        raise RuntimeError("GitHub returned malformed pull request metadata")
    if pull.get("number") != number:
        raise RuntimeError("GitHub returned another pull request")
    validate_candidate(pull, repository, head_sha)
    return pull


def _validate_current_run(
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
    repository_payload = run.get("repository")
    head_repository = run.get("head_repository")
    head_commit = run.get("head_commit")
    pull_entries = run.get("pull_requests")
    if not isinstance(pull_entries, list):
        raise ValueError("publisher Actions run lacks pull-request metadata")
    matching_pulls = [
        item
        for item in pull_entries
        if isinstance(item, Mapping)
        and item.get("number") == number
        and isinstance(item.get("head"), Mapping)
        and item["head"].get("sha") == head.get("sha")
        and isinstance(item.get("base"), Mapping)
        and item["base"].get("sha") == base.get("sha")
    ]
    referenced_workflows = run.get("referenced_workflows")
    if not isinstance(referenced_workflows, list) or not all(
        isinstance(item, Mapping) for item in referenced_workflows
    ):
        raise ValueError("publisher Actions run lacks referenced-workflow metadata")
    if runtime.get("workflow_file_path") == WORKFLOW_PATH:
        platform_sha = runtime.get("action_ref", "")
        referenced_source = referenced_workflows[0] if len(referenced_workflows) == 1 else {}
        authored_selector = referenced_source.get("path")
        canonical_ref = referenced_source.get("ref")
        resolved_sha = referenced_source.get("sha")
        expected_selector = f"{REUSABLE_WORKFLOW_PATH}@{platform_sha}"
        if (
            not FULL_SHA.fullmatch(platform_sha)
            or len(referenced_workflows) != 1
            or authored_selector != expected_selector
            or resolved_sha != platform_sha
            # GitHub omits the canonical ref when the authored selector is a
            # literal commit SHA.  A branch/tag ref would prove mutable source.
            or canonical_ref is not None
        ):
            raise ValueError("reusable workflow source is not an immutable literal SHA")
    elif referenced_workflows:
        raise ValueError("AI publisher run unexpectedly references another workflow")
    workflow_id = run.get("workflow_id")
    if (
        run.get("id") != int(runtime["run_id"])
        or run.get("url") != (f"{API_URL}/repos/{repository}/actions/runs/{runtime['run_id']}")
        or run.get("html_url") != (f"{SERVER_URL}/{repository}/actions/runs/{runtime['run_id']}")
        or run.get("run_attempt") != int(runtime["run_attempt"])
        or not isinstance(run.get("run_number"), int)
        or run["run_number"] < 1
        or not isinstance(workflow_id, int)
        or workflow_id < 1
        or run.get("workflow_url") != (f"{API_URL}/repos/{repository}/actions/workflows/{workflow_id}")
        or run.get("event") != "pull_request_target"
        or run.get("status") != "in_progress"
        or run.get("conclusion") is not None
        # REST exposes the PR head for pull_request_target runs.  The
        # protected default-branch source is bound separately by
        # job.workflow_sha and pull_requests[].base.sha.
        or run.get("head_sha") != head.get("sha")
        or run.get("head_branch") != head.get("ref")
        or not isinstance(head_commit, Mapping)
        or head_commit.get("id") != head.get("sha")
        or run.get("path") != runtime.get("workflow_file_path")
        or not isinstance(repository_payload, Mapping)
        or str(repository_payload.get("id")) != runtime["repository_id"]
        or repository_payload.get("full_name") != repository
        or not isinstance(head_repository, Mapping)
        or head_repository.get("full_name") != repository
        or str(head_repository.get("id")) != runtime["repository_id"]
        or len(pull_entries) != 1
        or len(matching_pulls) != 1
    ):
        raise ValueError("publisher Actions run identity is invalid")


def paginated_workflow_runs(
    repository: str,
    workflow_id: int,
    *,
    token: str,
) -> list[Mapping[str, Any]]:
    if isinstance(workflow_id, bool) or not isinstance(workflow_id, int):
        raise ValueError("publisher workflow ID is malformed")
    if workflow_id < 1:
        raise ValueError("publisher workflow ID is malformed")
    values: list[Mapping[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (
                f"/repos/{repository}/actions/workflows/{workflow_id}/runs"
                f"?event=pull_request_target&exclude_pull_requests=false"
                f"&per_page=100&page={page}"
            ),
            token=token,
        )
        runs = payload.get("workflow_runs") if isinstance(payload, Mapping) else None
        if not isinstance(runs, list) or not all(isinstance(item, Mapping) for item in runs):
            raise RuntimeError("GitHub returned malformed workflow-run pagination")
        total = payload.get("total_count") if isinstance(payload, Mapping) else None
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or (expected_total is not None and total != expected_total)
        ):
            raise RuntimeError("GitHub returned malformed workflow-run total")
        expected_total = total
        values.extend(runs)
        if len(runs) < 100:
            if len(values) != expected_total:
                raise RuntimeError("GitHub workflow-run pagination was truncated")
            return values
    raise RuntimeError("workflow-run pagination exceeded the bounded page limit")


def _candidate_run_key(run: Mapping[str, Any]) -> tuple[int, int, int]:
    values: list[int] = []
    for field in ("run_number", "run_attempt", "id"):
        value = run.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"candidate workflow run has invalid {field}")
        values.append(value)
    return values[0], values[1], values[2]


def _same_prt_candidate(
    candidate: Mapping[str, Any],
    *,
    current: Mapping[str, Any],
    pull: Mapping[str, Any],
    repository: str,
) -> bool:
    head = pull["head"]
    base = pull["base"]
    assert isinstance(head, Mapping) and isinstance(base, Mapping)
    candidate_repository = candidate.get("repository")
    candidate_head_repository = candidate.get("head_repository")
    if (
        candidate.get("workflow_id") != current.get("workflow_id")
        or candidate.get("event") != "pull_request_target"
        or candidate.get("path") != current.get("path")
        or candidate.get("head_sha") != head.get("sha")
        or candidate.get("head_branch") != head.get("ref")
        or not isinstance(candidate_repository, Mapping)
        or candidate_repository.get("full_name") != repository
        or not isinstance(candidate_head_repository, Mapping)
        or candidate_head_repository.get("full_name") != repository
        or candidate_head_repository.get("id") != candidate_repository.get("id")
    ):
        return False
    pull_entries = candidate.get("pull_requests")
    if not isinstance(pull_entries, list):
        raise ValueError("candidate workflow run has malformed pull requests")
    # startup_failure and other no-job runs can omit PR associations.  They
    # still supersede an older run on the exact workflow/head/branch.
    if not pull_entries:
        return True
    number = pull.get("number")
    return any(
        isinstance(item, Mapping)
        and item.get("number") == number
        and isinstance(item.get("head"), Mapping)
        and item["head"].get("sha") == head.get("sha")
        and isinstance(item.get("base"), Mapping)
        and item["base"].get("sha") == base.get("sha")
        for item in pull_entries
    )


def _is_effective_prt_candidate(run: Mapping[str, Any]) -> bool:
    """Ignore label-filtered skipped runs, but retain zero-job startup failures."""
    status = run.get("status")
    conclusion = run.get("conclusion")
    if status not in {"completed", "in_progress", "queued", "requested", "waiting", "pending"}:
        raise ValueError("candidate workflow run has invalid status")
    if status == "completed" and conclusion == "skipped":
        return False
    if status == "completed" and conclusion not in {
        "action_required",
        "cancelled",
        "failure",
        "neutral",
        "stale",
        "startup_failure",
        "success",
        "timed_out",
    }:
        raise ValueError("candidate workflow run has invalid conclusion")
    if status != "completed" and conclusion is not None:
        raise ValueError("incomplete candidate workflow run has a conclusion")
    return True


def assert_newest_prt_attempt(
    current: Mapping[str, Any],
    *,
    pull: Mapping[str, Any],
    repository: str,
    token: str,
) -> None:
    workflow_id = current.get("workflow_id")
    if isinstance(workflow_id, bool) or not isinstance(workflow_id, int):
        raise ValueError("publisher workflow ID is malformed")
    candidates = [
        run
        for run in paginated_workflow_runs(
            repository,
            workflow_id,
            token=token,
        )
        if _same_prt_candidate(
            run,
            current=current,
            pull=pull,
            repository=repository,
        )
        and _is_effective_prt_candidate(run)
    ]
    if not candidates:
        raise ValueError("publisher run is absent from complete workflow history")
    newest = max(candidates, key=_candidate_run_key)
    if _candidate_run_key(newest) != _candidate_run_key(current):
        raise ValueError("publisher run is superseded by a newer run or attempt")


def _upsert_check(
    repository: str,
    payload: Mapping[str, Any],
    *,
    token: str,
) -> int:
    checks = paginated_check_runs(
        repository,
        str(payload["head_sha"]),
        str(payload["name"]),
        token=token,
    )
    prior = _matching_owned_check(
        checks,
        str(payload["external_id"]),
        str(payload["name"]),
    )
    path: str
    method: str
    update_payload = dict(payload)
    if prior is None:
        method = "POST"
        path = f"/repos/{repository}/check-runs"
    else:
        method = "PATCH"
        path = f"/repos/{repository}/check-runs/{prior['id']}"
        update_payload.pop("head_sha", None)
    try:
        response = api_request(
            method,
            path,
            token=token,
            payload=update_payload,
            ambiguous_write=True,
        )
        if not isinstance(response, Mapping) or not isinstance(response.get("id"), int):
            raise RuntimeError("GitHub returned malformed check-write response")
        return int(response["id"])
    except AmbiguousWriteError:
        reconciled = _matching_owned_check(
            paginated_check_runs(
                repository,
                str(payload["head_sha"]),
                str(payload["name"]),
                token=token,
            ),
            str(payload["external_id"]),
            str(payload["name"]),
        )
        if reconciled is None:
            raise
        return int(reconciled["id"])


def _cancel_written_check(
    repository: str,
    check_id: int,
    payload: Mapping[str, Any],
    *,
    token: str,
) -> None:
    expected = dict(payload)
    expected["conclusion"] = "cancelled"
    expected["output"] = {
        "title": f"{payload['name']}: cancelled",
        "summary": "The pull-request head changed during publication.",
    }
    update = dict(expected)
    update.pop("head_sha", None)
    for attempt in range(2):
        with contextlib.suppress(AmbiguousWriteError):
            api_request(
                "PATCH",
                f"/repos/{repository}/check-runs/{check_id}",
                token=token,
                payload=update,
                ambiguous_write=True,
            )
        # A timed-out cancellation is safety-critical: reconcile the exact
        # check before deciding whether one bounded retry is needed.
        readback = api_request(
            "GET",
            f"/repos/{repository}/check-runs/{check_id}",
            token=token,
        )
        if not isinstance(readback, Mapping):
            raise RuntimeError("GitHub returned malformed cancellation readback")
        try:
            validate_written_check(readback, expected)
        except RuntimeError:
            if attempt == 0:
                continue
            raise
        return
    raise RuntimeError("check cancellation could not be reconciled")


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repository or "/" not in repository:
        raise ValueError("trusted GitHub token or repository context is unavailable")
    raw_number = os.environ["INPUT_PULL_REQUEST_NUMBER"]
    if not raw_number.isdecimal() or int(raw_number) < 1:
        raise ValueError("invalid pull request number")
    number = int(raw_number)
    head_sha = os.environ["INPUT_EXPECTED_HEAD_SHA"]
    runtime = {
        "action_ref": os.environ.get("ACTION_REF", ""),
        "action_repository": os.environ.get("ACTION_REPOSITORY", ""),
        "api_url": os.environ.get("RUNTIME_API_URL", ""),
        "server_url": os.environ.get("RUNTIME_SERVER_URL", ""),
        "event_name": os.environ.get("RUNTIME_EVENT_NAME", ""),
        "job_id": os.environ.get("RUNTIME_JOB_ID", ""),
        "job_check_run_id": os.environ.get("RUNTIME_JOB_CHECK_RUN_ID", ""),
        "run_id": os.environ.get("RUNTIME_RUN_ID", ""),
        "run_attempt": os.environ.get("RUNTIME_RUN_ATTEMPT", ""),
        "repository_id": os.environ.get("RUNTIME_REPOSITORY_ID", ""),
        "workflow_ref": os.environ.get("RUNTIME_WORKFLOW_REF", ""),
        "workflow_sha": os.environ.get("RUNTIME_WORKFLOW_SHA", ""),
        "workflow_repository": os.environ.get("RUNTIME_WORKFLOW_REPOSITORY", ""),
        "workflow_file_path": os.environ.get("RUNTIME_WORKFLOW_FILE_PATH", ""),
    }
    context = resolve_context(runtime["workflow_file_path"], runtime["job_id"])
    pull = _fetch_pull(repository, number, head_sha, token=token)
    validate_runtime(runtime, pull, repository, context)
    run = api_request(
        "GET",
        f"/repos/{repository}/actions/runs/{runtime['run_id']}",
        token=token,
    )
    if not isinstance(run, Mapping):
        raise RuntimeError("GitHub returned malformed Actions run metadata")
    _validate_current_run(
        run,
        runtime=runtime,
        pull=pull,
        repository=repository,
        number=number,
    )
    assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )
    evidence_digest = os.environ["INPUT_EVIDENCE_DIGEST"]
    conclusion = derive_conclusion(
        context,
        upstream_result=os.environ["INPUT_UPSTREAM_RESULT"],
        gate_passed=os.environ["INPUT_GATE_PASSED"],
        coverage_upload_result=os.environ["INPUT_COVERAGE_UPLOAD_RESULT"],
        evidence_digest=evidence_digest,
    )
    if context == "Security / required":
        if conclusion == "success":
            base = pull.get("base")
            if not isinstance(base, Mapping):
                raise ValueError("pull request base metadata is missing")
            deepsource = poll_deepsource(
                repository,
                head_sha,
                str(base.get("sha") or ""),
                token=token,
            )
            if not deepsource.passing:
                conclusion = "failure"
        else:
            deepsource = _deepsource_evaluation(
                "not-evaluated",
                policy=None,
                details=(f"upstream conclusion: {conclusion}",),
            )
        deepsource_evidence_digest = deepsource.evidence_digest
    else:
        deepsource_evidence_digest = "not-applicable"
    identity = {
        "repository": repository,
        "repository_id": runtime["repository_id"],
        "pull_request_number": str(number),
        "head_sha": head_sha,
        "context": context,
        "workflow_ref": runtime["workflow_ref"],
        "workflow_sha": runtime["workflow_sha"],
        "run_id": runtime["run_id"],
        "run_attempt": runtime["run_attempt"],
        "evidence_digest": evidence_digest,
        "deepsource_evidence_digest": deepsource_evidence_digest,
        "action_ref": runtime["action_ref"],
        "job_id": runtime["job_id"],
        "job_check_run_id": runtime["job_check_run_id"],
    }
    payload = build_check_payload(identity, conclusion)
    # Refetch directly before the external write.
    pull = _fetch_pull(repository, number, head_sha, token=token)
    assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )
    check_id = _upsert_check(repository, payload, token=token)
    try:
        pull = _fetch_pull(repository, number, head_sha, token=token)
        assert_newest_prt_attempt(
            run,
            pull=pull,
            repository=repository,
            token=token,
        )
    except (ValueError, RuntimeError):
        _cancel_written_check(
            repository,
            check_id,
            payload,
            token=token,
        )
        raise
    readback = api_request(
        "GET",
        f"/repos/{repository}/check-runs/{check_id}",
        token=token,
    )
    if not isinstance(readback, Mapping):
        raise RuntimeError("GitHub returned malformed check readback")
    validate_written_check(readback, payload)
    try:
        pull = _fetch_pull(repository, number, head_sha, token=token)
        assert_newest_prt_attempt(
            run,
            pull=pull,
            repository=repository,
            token=token,
        )
    except (ValueError, RuntimeError):
        _cancel_written_check(
            repository,
            check_id,
            payload,
            token=token,
        )
        raise
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("published=true\n")
        output.write(f"conclusion={conclusion}\n")


if __name__ == "__main__":
    main()
