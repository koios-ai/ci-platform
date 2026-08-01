"""Fail-closed, exact-head orchestration for Koios CI finalization.

Provider success requires bounded native review, App-delivery, and check
evidence plus a complete paginated GraphQL review-thread snapshot. Hosted
provider canary flags remain separate fail-closed cutover controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

SCHEMA_VERSION = "koios-ci-finalizer-state-v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DEPENDABOT_LOGIN = "dependabot[bot]"
FINAL_LABELS = ("ci-final", "ai-review-ready")
MAX_POLL_SECONDS = 900
MAX_POLL_INTERVAL_SECONDS = 60
MAX_API_PAGES = 10
MAX_STATE_BYTES = 1024 * 1024
MAX_REPOSITORY_CHARS = 200
MAX_EXTERNAL_STRING_CHARS = 16_384
MAX_EXTERNAL_COLLECTION_ITEMS = 1_000
MAX_EXTERNAL_NODES = 20_000
MAX_EXTERNAL_DEPTH = 16
MAX_EXTERNAL_REASON_CHARS = 256
GITHUB_API_VERSION = "2026-03-10"
WORKFLOW_PATH_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
RUN_PATH_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@(?:refs/heads/)?[A-Za-z0-9._/-]+$")
SOURCE_PATH_RE = re.compile(r"^koios-ai/ci-platform/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}$")
FINALIZER_RUN_NAME = "koios-finalizer-v1"
FINAL_SUBJECT_RUN_NAME = "koios-final-subject-v1"

TOP_LEVEL_STATE_FIELDS = {
    "schema_version",
    "key",
    "base_sha",
    "phase",
    "dry_run",
    "workflow",
    "controller_run",
    "subject_run",
    "gates",
    "labels",
    "providers",
    "dependabot",
    "rerun_requests",
    "blockers",
    "complete",
    "updated_at",
}

PROVIDER_FAILURE_MARKERS = (
    "rate limit",
    "rate-limit",
    "usage limit",
    "quota",
    "out of credits",
    "credit limit",
    "provider error",
    "provider unavailable",
    "outage",
    "review skipped",
)


class ProviderUnavailable(RuntimeError):
    """A provider readback failed for a reason that must block finalization."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AmbiguousMutation(RuntimeError):
    """A write may have succeeded; callers must reconcile from live state."""


class GitHubAPIError(RuntimeError):
    """A bounded GitHub API request failed."""


class StateConflictError(RuntimeError):
    """Another process changed or currently owns the exact-head state."""


class StatePersistenceError(RuntimeError):
    """Atomic state persistence failed before authority could be replaced."""


class BoundaryViolation(RuntimeError):
    """The repository, pull request, or head moved outside the closed attempt."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _bounded_failure_reason(exc: BaseException) -> str:
    """Return a closed identifier without persisting provider-controlled text."""
    if not isinstance(exc, ProviderUnavailable):
        return type(exc).__name__
    reason = exc.reason
    if (
        isinstance(reason, str)
        and 0 < len(reason) <= MAX_EXTERNAL_REASON_CHARS
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]*", reason)
    ):
        return reason
    return "unbounded-provider-error"


@dataclass(frozen=True)
class WorkflowIdentity:
    workflow_id: int
    path: str
    sha: str
    event: str
    source_path: str
    promoter: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.workflow_id) is not int or self.workflow_id <= 0:
            raise ValueError("workflow_id must be positive")
        if len(self.path) > 256 or not WORKFLOW_PATH_RE.fullmatch(self.path):
            raise ValueError("workflow path must be one YAML file under .github/workflows")
        if not SHA_RE.fullmatch(self.sha):
            raise ValueError("workflow sha must be a full lowercase commit SHA")
        if self.event != "workflow_dispatch":
            raise ValueError("the trusted controller must use workflow_dispatch")
        if (
            len(self.source_path) > 512
            or not SOURCE_PATH_RE.fullmatch(self.source_path)
            or not self.source_path.endswith(f"@{self.sha}")
        ):
            raise ValueError("source path must be the immutable Koios platform workflow")
        if _actor_projection(self.promoter) is None:
            raise ValueError("workflow promoter must contain login, id, and type")


@dataclass(frozen=True)
class ControllerIdentity:
    path: str
    event: str
    repository: str
    repository_id: int
    run_id: int
    run_attempt: int
    sha: str
    ref: str

    def __post_init__(self) -> None:
        if len(self.path) > 256 or not WORKFLOW_PATH_RE.fullmatch(self.path):
            raise ValueError("controller workflow path must name one direct YAML file")
        if self.event != "workflow_dispatch":
            raise ValueError("controller must use workflow_dispatch")
        if len(self.repository) > MAX_REPOSITORY_CHARS or not REPOSITORY_RE.fullmatch(self.repository):
            raise ValueError("controller repository must be OWNER/REPO")
        if type(self.repository_id) is not int or self.repository_id <= 0:
            raise ValueError("controller repository id must be positive")
        if type(self.run_id) is not int or type(self.run_attempt) is not int:
            raise ValueError("controller run id and attempt must be integers")
        if self.run_id <= 0 or self.run_attempt <= 0:
            raise ValueError("controller run id and attempt must be positive")
        if not SHA_RE.fullmatch(self.sha):
            raise ValueError("controller sha must be a full lowercase commit SHA")
        if (
            len(self.ref) > 256
            or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", self.ref)
            or ".." in self.ref
            or "//" in self.ref
        ):
            raise ValueError("controller ref must be a closed branch ref")


@dataclass(frozen=True)
class ProviderIdentity:
    name: str
    login: str
    app_id: int
    app_slug: str
    check_name: str | None


DEFAULT_PROVIDERS = (
    ProviderIdentity(
        name="coderabbit",
        login="coderabbitai[bot]",
        app_id=347564,
        app_slug="coderabbitai",
        check_name="CodeRabbit",
    ),
    ProviderIdentity(
        name="codex",
        login="chatgpt-codex-connector[bot]",
        app_id=1144995,
        app_slug="chatgpt-codex-connector",
        check_name=None,
    ),
)


@dataclass(frozen=True)
class FinalizerConfig:
    workflow: WorkflowIdentity | None
    controller: ControllerIdentity | None = None
    subject_run_id: int | None = None
    subject_run_attempt: int | None = None
    gate_jobs: Mapping[str, str] = field(
        default_factory=lambda: {
            "deterministic": "Platform / deterministic final evidence",
            "security": "Platform / security evidence",
            "coverage": "Platform / coverage evidence verification",
        }
    )
    provider_contract_verified: bool = False
    codex_hosted_canary_verified: bool = False
    invalidation_controller_verified: bool = False
    latest_run_inventory_verified: bool = False
    external_singleflight_verified: bool = False
    providers: tuple[ProviderIdentity, ...] = DEFAULT_PROVIDERS

    def __post_init__(self) -> None:
        if set(self.gate_jobs) != {"deterministic", "security", "coverage"}:
            raise ValueError("gate_jobs must define deterministic, security, and coverage")
        if len(set(self.gate_jobs.values())) != 3:
            raise ValueError("gate job names must be unique")
        if tuple(provider.name for provider in self.providers) != (
            "coderabbit",
            "codex",
        ):
            raise ValueError("provider identities must be the closed CodeRabbit/Codex tuple")
        subject_values = (self.subject_run_id, self.subject_run_attempt)
        if any(value is not None for value in subject_values) and any(
            type(value) is not int or value <= 0 for value in subject_values
        ):
            raise ValueError("subject run id and attempt must both be positive integers")
        if (
            self.controller is not None
            and self.subject_run_id is not None
            and self.controller.run_id == self.subject_run_id
        ):
            raise ValueError("controller and subject run ids must be distinct")


class FinalizerAPI(Protocol):
    def get_repository(self, repository: str) -> dict[str, Any]: ...

    def get_pull(self, repository: str, number: int) -> dict[str, Any]: ...

    def get_workflow_run(self, repository: str, run_id: int) -> dict[str, Any]: ...

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
    ) -> dict[str, Any]: ...

    def list_run_jobs(
        self,
        repository: str,
        run_id: int,
        attempt: int,
    ) -> dict[str, Any]: ...

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
    ) -> dict[str, Any]: ...

    def add_labels(
        self,
        repository: str,
        number: int,
        labels: tuple[str, ...],
    ) -> None: ...

    def get_pull_labels(self, repository: str, number: int) -> set[str]: ...

    def remove_label(self, repository: str, number: int, label: str) -> None: ...

    def provider_snapshot(
        self,
        repository: str,
        number: int,
        head_sha: str,
    ) -> dict[str, Any]: ...


class GitHubRestAPI:
    """Small stdlib GitHub REST adapter with bounded pagination and timeouts."""

    api_root = "https://api.github.com"

    def __init__(self, token: str, *, timeout_seconds: int = 20) -> None:
        if not token.startswith("ghs_"):
            raise ValueError(
                "only an ephemeral GitHub Actions installation token (ghs_) is "
                "accepted; personal access and OAuth tokens are forbidden"
            )
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("HTTP timeout must be between 1 and 60 seconds")
        self._token = token
        self._timeout_seconds = timeout_seconds

    @classmethod
    def from_environment(cls) -> GitHubRestAPI:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise RuntimeError(
                "GITHUB_TOKEN is required and must be an ephemeral Actions "
                "installation token; this command never requests a PAT"
            )
        return cls(token)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str | int] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.api_root}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "koios-ci-finalizer-v1",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in {403, 429}:
                raise ProviderUnavailable("rate-limit") from exc
            if method != "GET" and exc.code >= 500:
                raise AmbiguousMutation(f"GitHub write returned HTTP {exc.code}; live readback required") from exc
            raise GitHubAPIError(f"GitHub API returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if method != "GET":
                raise AmbiguousMutation("GitHub write timed out; live readback required") from exc
            raise ProviderUnavailable("outage") from exc
        if len(raw) > 4 * 1024 * 1024:
            raise GitHubAPIError("GitHub API response exceeded 4 MiB")
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAPIError("GitHub API returned malformed JSON") from exc

    def _paginate(
        self,
        path: str,
        key: str | None = None,
        *,
        query: Mapping[str, str | int] | None = None,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        base_query = dict(query or {})
        base_query["per_page"] = 100
        for page in range(1, MAX_API_PAGES + 1):
            page_query = {**base_query, "page": page}
            payload = self._request("GET", path, query=page_query)
            items = payload.get(key, []) if key else payload
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise GitHubAPIError("GitHub API pagination payload was malformed")
            rows.extend(items)
            if len(items) < 100:
                return rows
        raise GitHubAPIError("GitHub API pagination exceeded the closed page limit")

    def _graphql(self, query: str, variables: Mapping[str, Any]) -> dict[str, Any]:
        payload = _require_dict(
            self._request(
                "POST",
                "/graphql",
                payload={"query": query, "variables": dict(variables)},
            )
        )
        if payload.get("errors"):
            raise GitHubAPIError("GitHub GraphQL returned errors")
        return _require_dict(payload.get("data"))

    def get_repository(self, repository: str) -> dict[str, Any]:
        return _require_dict(self._request("GET", f"/repos/{repository}"))

    def get_pull(self, repository: str, number: int) -> dict[str, Any]:
        return _require_dict(self._request("GET", f"/repos/{repository}/pulls/{number}"))

    def get_workflow_run(self, repository: str, run_id: int) -> dict[str, Any]:
        return _require_dict(self._request("GET", f"/repos/{repository}/actions/runs/{run_id}"))

    def list_run_jobs(
        self,
        repository: str,
        run_id: int,
        attempt: int,
    ) -> dict[str, Any]:
        payload = _require_dict(
            self._request(
                "GET",
                (f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"),
                query={"per_page": 100},
            )
        )
        jobs_value = payload.get("jobs")
        if not isinstance(jobs_value, list):
            raise GitHubAPIError("run jobs payload was malformed")
        return {
            "run_id": run_id,
            "run_attempt": attempt,
            "total_count": payload.get("total_count"),
            "jobs": jobs_value,
        }

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
        repository_payload = self.get_repository(repository)
        pull_payload = self.get_pull(repository, number)
        controller = self.get_workflow_run(repository, controller_run_id)
        subject = self.get_workflow_run(repository, subject_run_id)
        repository_id = repository_payload.get("id")
        default_branch = repository_payload.get("default_branch")
        head = pull_payload.get("head")
        base = pull_payload.get("base")
        expected_title = (
            f"{FINALIZER_RUN_NAME}|repo={repository_id}|pr={number}|head={head_sha}|base={base_sha}"
            f"|subject={subject_run_id}|attempt={subject_attempt}"
        )
        if (
            type(repository_id) is not int
            or repository_id <= 0
            or not isinstance(default_branch, str)
            or not default_branch
            or not isinstance(head, dict)
            or not isinstance(base, dict)
            or head.get("sha") != head_sha
            or base.get("sha") != base_sha
            or controller.get("display_title") != expected_title
            or controller.get("id") != controller_run_id
            or controller.get("run_attempt") != controller_attempt
            or controller.get("event") != "workflow_dispatch"
            or controller.get("head_branch") != default_branch
            or subject.get("id") != subject_run_id
            or subject.get("run_attempt") != subject_attempt
        ):
            raise GitHubAPIError("workflow source binding is incomplete or stale")
        controller_path = _normalized_run_workflow_path(controller.get("path"), default_branch)
        subject_path = _normalized_run_workflow_path(subject.get("path"), default_branch)
        controller_sha = _require_sha(controller.get("head_sha"), "controller head")
        subject_sha = _require_sha(subject.get("head_sha"), "subject head")
        workflow_id = subject.get("workflow_id")
        controller_workflow_id = controller.get("workflow_id")
        if (
            type(workflow_id) is not int
            or workflow_id <= 0
            or type(controller_workflow_id) is not int
            or controller_workflow_id <= 0
        ):
            raise GitHubAPIError("workflow source identity is malformed")
        referenced = subject.get("referenced_workflows")
        if not isinstance(referenced, list):
            raise GitHubAPIError("referenced workflow provenance is absent")
        platform_sources = [
            item
            for item in referenced
            if isinstance(item, dict) and isinstance(item.get("path"), str) and SOURCE_PATH_RE.fullmatch(item["path"])
        ]
        if len(platform_sources) != 1:
            raise GitHubAPIError("immutable platform source is missing or ambiguous")
        platform_source = platform_sources[0]
        authored_selector = platform_source["path"]
        resolved_sha = _require_sha(platform_source.get("sha"), "resolved platform source")
        if authored_selector.rsplit("@", 1)[-1] != resolved_sha or platform_source.get("ref") not in {
            None,
            resolved_sha,
        }:
            raise GitHubAPIError("authored and resolved platform sources do not match")
        promoter = _actor_projection(controller.get("actor"))
        if promoter is None or _actor_projection(controller.get("triggering_actor")) != promoter:
            raise GitHubAPIError("controller promoter identity is incomplete")
        return {
            "readback": "complete",
            "schema_version": "koios-run-source-v3",
            "repository_id": repository_id,
            "pull_request": number,
            "pr_head_sha": head_sha,
            "base_sha": base_sha,
            "controller_run_id": controller_run_id,
            "controller_run_attempt": controller_attempt,
            "controller_workflow_id": controller_workflow_id,
            "controller_path": controller_path,
            "controller_sha": controller_sha,
            "controller_ref": f"refs/heads/{default_branch}",
            "controller_event": controller["event"],
            "subject_run_id": subject_run_id,
            "subject_run_attempt": subject_attempt,
            "subject_workflow_id": workflow_id,
            "subject_path": subject_path,
            "subject_sha": subject_sha,
            "authored_source_selector": authored_selector,
            "resolved_source_sha": resolved_sha,
            "source_path": authored_selector,
            "source_sha": resolved_sha,
            "promoter": promoter,
        }

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
        repository_payload = self.get_repository(repository)
        repository_id = repository_payload.get("id")
        if type(repository_id) is not int or repository_id <= 0:
            raise GitHubAPIError("repository identity is malformed")
        expected_title = (
            f"{FINAL_SUBJECT_RUN_NAME}|repo={repository_id}|pr={number}|head={head_sha}"
            f"|base={base_sha}|platform={platform_sha}"
        )
        rows = self._paginate(
            f"/repos/{repository}/actions/workflows/{workflow_id}/runs",
            "workflow_runs",
            query={"event": "workflow_dispatch"},
        )
        attempts: list[dict[str, Any]] = []
        for row in rows:
            if row.get("display_title") != expected_title:
                continue
            run_id = row.get("id")
            run_attempt = row.get("run_attempt")
            if (
                type(run_id) is not int
                or run_id <= 0
                or type(run_attempt) is not int
                or not 1 <= run_attempt <= 100
                or row.get("workflow_id") != workflow_id
            ):
                raise GitHubAPIError("same-head workflow inventory row is malformed")
            for attempt in range(1, run_attempt + 1):
                attempt_row = (
                    row
                    if attempt == run_attempt
                    else _require_dict(
                        self._request(
                            "GET",
                            f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}",
                        )
                    )
                )
                jobs_payload = self.list_run_jobs(repository, run_id, attempt)
                attempts.append(
                    {
                        "id": run_id,
                        "attempt": attempt,
                        "workflow_id": attempt_row.get("workflow_id"),
                        "display_title": attempt_row.get("display_title"),
                        "status": attempt_row.get("status"),
                        "conclusion": attempt_row.get("conclusion"),
                        "created_at": attempt_row.get("created_at"),
                        "updated_at": attempt_row.get("updated_at"),
                        "total_jobs": jobs_payload.get("total_count"),
                    }
                )
        attempts.sort(key=lambda item: (str(item["created_at"]), int(item["id"]), int(item["attempt"])))
        return {
            "readback": "complete",
            "repository_id": repository_id,
            "pull_request": number,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "workflow_id": workflow_id,
            "selected_run_id": selected_run_id,
            "selected_attempt": selected_attempt,
            "platform_sha": platform_sha,
            "runs": attempts,
        }

    def add_labels(
        self,
        repository: str,
        number: int,
        labels: tuple[str, ...],
    ) -> None:
        self._request(
            "POST",
            f"/repos/{repository}/issues/{number}/labels",
            payload={"labels": list(labels)},
        )

    def get_pull_labels(self, repository: str, number: int) -> set[str]:
        pull_payload = self.get_pull(repository, number)
        labels = pull_payload.get("labels")
        if not isinstance(labels, list):
            raise GitHubAPIError("pull request label readback was malformed")
        result: set[str] = set()
        for item in labels:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise GitHubAPIError("pull request label entry was malformed")
            result.add(item["name"])
        return result

    def remove_label(self, repository: str, number: int, label: str) -> None:
        encoded = urllib.parse.quote(label, safe="")
        self._request(
            "DELETE",
            f"/repos/{repository}/issues/{number}/labels/{encoded}",
        )

    def provider_snapshot(
        self,
        repository: str,
        number: int,
        head_sha: str,
    ) -> dict[str, Any]:
        reviews = self._paginate(f"/repos/{repository}/pulls/{number}/reviews")
        issue_comments = self._paginate(f"/repos/{repository}/issues/{number}/comments")
        review_comments = self._paginate(f"/repos/{repository}/pulls/{number}/comments")
        checks = self._paginate(
            f"/repos/{repository}/commits/{head_sha}/check-runs",
            "check_runs",
            query={"filter": "all"},
        )
        threads = self._complete_review_threads(repository, number)
        return {
            "readback": "complete",
            "reviews": reviews,
            "issue_comments": issue_comments,
            "review_comments": review_comments,
            "checks": checks,
            "threads": threads,
        }

    def _complete_review_threads(self, repository: str, number: int) -> dict[str, Any]:
        owner, name = repository.split("/", 1)
        query = """
        query ReviewThreads($owner: String!, $name: String!, $number: Int!, $threadsCursor: String) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) {
              reviewThreads(first: 100, after: $threadsCursor) {
                nodes {
                  id
                  isResolved
                  comments(first: 100) {
                    nodes { author { login } }
                    pageInfo { hasNextPage endCursor }
                  }
                }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
        """
        comment_query = """
        query ReviewThreadComments($threadId: ID!, $commentsCursor: String) {
          node(id: $threadId) {
            ... on PullRequestReviewThread {
              comments(first: 100, after: $commentsCursor) {
                nodes { author { login } }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
        """
        thread_nodes: list[dict[str, Any]] = []
        threads_cursor: str | None = None
        for _page in range(MAX_API_PAGES):
            data = self._graphql(
                query,
                {
                    "owner": owner,
                    "name": name,
                    "number": number,
                    "threadsCursor": threads_cursor,
                },
            )
            repository_data = _require_dict(data.get("repository"))
            pull_data = _require_dict(repository_data.get("pullRequest"))
            connection = _require_dict(pull_data.get("reviewThreads"))
            nodes = connection.get("nodes")
            page_info = _require_dict(connection.get("pageInfo"))
            if not isinstance(nodes, list) or not all(isinstance(node, dict) for node in nodes):
                raise GitHubAPIError("reviewThreads nodes are malformed")
            for node in nodes:
                thread_id = node.get("id")
                is_resolved = node.get("isResolved")
                comments = _require_dict(node.get("comments"))
                comment_nodes = comments.get("nodes")
                comment_page_info = _require_dict(comments.get("pageInfo"))
                if (
                    not isinstance(thread_id, str)
                    or not thread_id
                    or not isinstance(is_resolved, bool)
                    or not isinstance(comment_nodes, list)
                    or not all(isinstance(comment, dict) for comment in comment_nodes)
                ):
                    raise GitHubAPIError("review thread is malformed")
                closed_comments = list(comment_nodes)
                for _comment_page in range(MAX_API_PAGES):
                    if comment_page_info.get("hasNextPage") is False:
                        break
                    comments_cursor = comment_page_info.get("endCursor")
                    if not isinstance(comments_cursor, str) or not comments_cursor:
                        raise GitHubAPIError("review thread comment cursor is malformed")
                    comment_data = self._graphql(
                        comment_query,
                        {"threadId": thread_id, "commentsCursor": comments_cursor},
                    )
                    comment_connection = _require_dict(_require_dict(comment_data.get("node")).get("comments"))
                    next_nodes = comment_connection.get("nodes")
                    if not isinstance(next_nodes, list) or not all(isinstance(comment, dict) for comment in next_nodes):
                        raise GitHubAPIError("review thread comment nodes are malformed")
                    closed_comments.extend(next_nodes)
                    comment_page_info = _require_dict(comment_connection.get("pageInfo"))
                else:
                    raise GitHubAPIError("review thread comment pagination exceeded the closed limit")
                thread_nodes.append(
                    {
                        "isResolved": is_resolved,
                        "comments": {
                            "nodes": closed_comments,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        },
                    }
                )
            if page_info.get("hasNextPage") is False:
                return {
                    "nodes": thread_nodes,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            threads_cursor = page_info.get("endCursor")
            if not isinstance(threads_cursor, str) or not threads_cursor:
                raise GitHubAPIError("reviewThreads cursor is malformed")
        raise GitHubAPIError("reviewThreads pagination exceeded the closed page limit")


class Finalizer:
    def __init__(
        self,
        *,
        api: FinalizerAPI,
        state_dir: Path,
        config: FinalizerConfig,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.api = api
        self.state_dir = Path(state_dir)
        self.config = config
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep
        self._expected_state_digests: dict[Path, str | None] = {}

    def finalize(
        self,
        repository: str,
        number: int,
        *,
        dry_run: bool = False,
        rerun_failed: bool = False,
        timeout_seconds: int = 0,
        poll_seconds: int = 1,
    ) -> dict[str, Any]:
        _validate_command_inputs(repository, number, timeout_seconds, poll_seconds)
        repository_payload, pull_payload = self._read_boundary(repository, number)
        state = self._initial_state(
            repository,
            number,
            repository_payload,
            pull_payload,
            dry_run=dry_run,
        )
        return self._execute_serialized(
            state,
            pull_payload,
            rerun_failed=rerun_failed,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )

    def resume(
        self,
        repository: str,
        number: int,
        head_sha: str,
        *,
        dry_run: bool = False,
        rerun_failed: bool = False,
        timeout_seconds: int = 0,
        poll_seconds: int = 1,
    ) -> dict[str, Any]:
        _validate_command_inputs(repository, number, timeout_seconds, poll_seconds)
        _require_sha(head_sha, "head")
        try:
            state = self._load(repository, number, head_sha)
        except FileNotFoundError:
            repository_payload, pull_payload = self._read_boundary(
                repository,
                number,
                expected_head=head_sha,
            )
            state = self._initial_state(
                repository,
                number,
                repository_payload,
                pull_payload,
                dry_run=dry_run,
            )
        else:
            try:
                _, pull_payload = self._read_boundary(
                    repository,
                    number,
                    expected_head=head_sha,
                    expected_repository_id=state["key"]["repository_id"],
                    expected_base=state["base_sha"],
                )
            except BoundaryViolation as exc:
                state["complete"] = False
                state["phase"] = "blocked"
                _set_blockers(state, [(exc.code, exc.detail)])
                return self._finish(state, persist=not dry_run)
        state["dry_run"] = dry_run
        state["complete"] = False
        _set_blockers(state, [])
        return self._execute_serialized(
            state,
            pull_payload,
            rerun_failed=rerun_failed,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )

    def status(
        self,
        repository: str,
        number: int,
        head_sha: str,
    ) -> dict[str, Any]:
        _validate_command_inputs(repository, number, 0, 1)
        _require_sha(head_sha, "head")
        try:
            state = self._load(repository, number, head_sha)
        except FileNotFoundError:
            repository_payload, pull_payload = self._read_boundary(
                repository,
                number,
                expected_head=head_sha,
            )
            state = self._initial_state(
                repository,
                number,
                repository_payload,
                pull_payload,
                dry_run=True,
            )
        else:
            try:
                _, pull_payload = self._read_boundary(
                    repository,
                    number,
                    expected_head=head_sha,
                    expected_repository_id=state["key"]["repository_id"],
                    expected_base=state["base_sha"],
                )
            except BoundaryViolation as exc:
                result = cast(dict[str, Any], json.loads(json.dumps(state)))
                result["complete"] = False
                result["phase"] = "blocked"
                _set_blockers(result, [(exc.code, exc.detail)])
                result["updated_at"] = self._timestamp()
                validate_state(result)
                return result
        state["dry_run"] = True
        state["complete"] = False
        _set_blockers(state, [])
        return self._execute(
            state,
            pull_payload,
            rerun_failed=False,
            timeout_seconds=0,
            poll_seconds=1,
        )

    def _execute_serialized(
        self,
        state: dict[str, Any],
        pull_payload: dict[str, Any],
        *,
        rerun_failed: bool,
        timeout_seconds: int,
        poll_seconds: int,
    ) -> dict[str, Any]:
        """Serialize external mutations for one exact head in this state store."""

        key = state["key"]
        state_path = self._path(
            key["repository"],
            key["pull_request"],
            key["head_sha"],
        )
        operation_lock = state_path.with_suffix(".json.operation.lock")
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return self._block(
                state,
                "state-operation-lock-unavailable",
                "exact-head operation lock directory could not be created",
                persist=False,
            )

        lock_fd: int | None = None
        lock_identity: tuple[int, int] | None = None
        lock_token = f"{os.getpid()}:{os.urandom(16).hex()}\n".encode("ascii")
        try:
            lock_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                lock_flags |= os.O_BINARY
            try:
                lock_fd = os.open(operation_lock, lock_flags, 0o600)
            except FileExistsError:
                return self._block(
                    state,
                    "state-operation-conflict",
                    "another exact-head finalizer owns the external-mutation lease",
                    persist=False,
                )
            except OSError:
                return self._block(
                    state,
                    "state-operation-lock-unavailable",
                    "exact-head operation lock could not be acquired",
                    persist=False,
                )

            lock_stat = os.fstat(lock_fd)
            lock_identity = (lock_stat.st_dev, lock_stat.st_ino)
            if hasattr(os, "fchmod"):
                os.fchmod(lock_fd, 0o600)
            owned_lock_fd = lock_fd
            lock_fd = None
            with os.fdopen(owned_lock_fd, "wb", closefd=True) as lock_stream:
                lock_stream.write(lock_token)
                lock_stream.flush()
                os.fsync(lock_stream.fileno())
            self._fsync_directory(operation_lock.parent)
        except OSError:
            if lock_fd is not None:
                with suppress(OSError):
                    os.close(lock_fd)
            if lock_identity is not None and self._path_has_owned_token(
                operation_lock,
                lock_identity,
                lock_token,
            ):
                self._unlink_owned_path(operation_lock, lock_identity)
            return self._block(
                state,
                "state-operation-lock-unavailable",
                "exact-head operation lock could not be made durable",
                persist=False,
            )

        try:
            if state_path not in self._expected_state_digests:
                return self._block(
                    state,
                    "state-operation-stale-observation",
                    "exact-head state was not observed before acquiring the mutation lease",
                    persist=False,
                )
            expected_digest = self._expected_state_digests[state_path]
            try:
                current_raw = self._read_state_bytes(state_path)
            except FileNotFoundError:
                current_digest = None
            except (StatePersistenceError, ValueError):
                return self._block(
                    state,
                    "state-operation-stale-observation",
                    "exact-head state could not be revalidated after acquiring the mutation lease",
                    persist=False,
                )
            else:
                current_digest = hashlib.sha256(current_raw).hexdigest()
            if current_digest != expected_digest:
                return self._block(
                    state,
                    "state-operation-stale-observation",
                    "exact-head state changed before the external-mutation lease was acquired",
                    persist=False,
                )
            try:
                return self._execute(
                    state,
                    pull_payload,
                    rerun_failed=rerun_failed,
                    timeout_seconds=timeout_seconds,
                    poll_seconds=poll_seconds,
                )
            except Exception as exc:
                state["complete"] = False
                state["phase"] = "blocked"
                _set_blockers(
                    state,
                    [
                        (
                            "finalizer-execution-failed",
                            f"unexpected finalizer exception: {type(exc).__name__}",
                        )
                    ],
                )
                return self._finish(state, persist=True)
        finally:
            if lock_identity is not None and self._path_has_owned_token(
                operation_lock,
                lock_identity,
                lock_token,
            ):
                self._unlink_owned_path(operation_lock, lock_identity)

    def _initial_state(
        self,
        repository: str,
        number: int,
        repository_payload: dict[str, Any],
        pull_payload: dict[str, Any],
        *,
        dry_run: bool,
    ) -> dict[str, Any]:
        workflow = self.config.workflow
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "key": {
                "repository": repository,
                "repository_id": repository_payload["id"],
                "pull_request": number,
                "head_sha": _pull_head_sha(pull_payload),
            },
            "base_sha": pull_payload["base"]["sha"],
            "phase": "created",
            "dry_run": dry_run,
            "workflow": (
                {
                    "id": workflow.workflow_id,
                    "path": workflow.path,
                    "sha": workflow.sha,
                    "event": workflow.event,
                    "source_path": workflow.source_path,
                    "promoter": _actor_projection(workflow.promoter),
                }
                if workflow
                else None
            ),
            "controller_run": None,
            "subject_run": None,
            "gates": {
                "deterministic": "pending",
                "security": "pending",
                "coverage": "pending",
            },
            "labels": {
                "ci-final": "pending",
                "ai-review-ready": "pending",
            },
            "providers": {
                "coderabbit": "pending",
                "codex": "pending",
            },
            "dependabot": {
                "eligible": False,
                "proof": "not-applicable",
            },
            "rerun_requests": [],
            "blockers": [],
            "complete": False,
            "updated_at": self._timestamp(),
        }
        self._observe_state_path(
            self._path(
                repository,
                number,
                state["key"]["head_sha"],
            )
        )
        validate_state(state)
        return state

    def _execute(
        self,
        state: dict[str, Any],
        pull_payload: dict[str, Any],
        *,
        rerun_failed: bool,
        timeout_seconds: int,
        poll_seconds: int,
    ) -> dict[str, Any]:
        repository = state["key"]["repository"]
        number = state["key"]["pull_request"]
        head_sha = state["key"]["head_sha"]
        workflow = self.config.workflow
        controller = self.config.controller
        subject_run_id = self.config.subject_run_id
        subject_run_attempt = self.config.subject_run_attempt
        if workflow is None or controller is None or subject_run_id is None or subject_run_attempt is None:
            return self._block(
                state,
                "workflow-identity-unconfigured",
                (
                    "controller identity, distinct subject run, immutable "
                    "workflow path, and platform SHA are not configured"
                ),
            )
        try:
            repository_payload, _ = self._read_boundary(
                repository,
                number,
                expected_head=head_sha,
                expected_repository_id=state["key"]["repository_id"],
                expected_base=state["base_sha"],
            )
        except BoundaryViolation as exc:
            return self._block(state, exc.code, exc.detail)
        controller_blocker = _validate_controller_boundary(
            controller,
            repository_payload,
            repository,
        )
        if controller_blocker:
            return self._block(state, *controller_blocker)

        controller_payload = self.api.get_workflow_run(
            repository,
            controller.run_id,
        )
        controller_identity_blocker = _validate_controller_run_identity(
            controller_payload,
            controller,
            workflow.promoter,
        )
        if controller_identity_blocker:
            return self._block(state, *controller_identity_blocker)
        state["controller_run"] = {
            "id": controller_payload["id"],
            "attempt": controller_payload["run_attempt"],
            "workflow_id": controller_payload["workflow_id"],
            "path": f"{controller.path}@{controller.ref}",
            "sha": controller_payload["head_sha"],
            "ref": controller.ref,
            "status": controller_payload["status"],
            "conclusion": controller_payload.get("conclusion"),
        }

        selected = self.api.get_workflow_run(
            repository,
            subject_run_id,
        )
        identity_blocker = _validate_subject_run_identity(
            selected,
            workflow,
            subject_run_id,
            subject_run_attempt,
            controller.ref,
        )
        if identity_blocker:
            return self._block(state, *identity_blocker)
        state["subject_run"] = {
            "id": selected["id"],
            "attempt": selected["run_attempt"],
            "workflow_id": selected["workflow_id"],
            "path": f"{workflow.path}@{controller.ref}",
            "sha": selected["head_sha"],
            "status": selected["status"],
            "conclusion": selected.get("conclusion"),
        }
        if selected["status"] != "completed":
            return self._block(
                state,
                "workflow-not-terminal",
                "explicit subject workflow attempt is not completed",
            )
        if selected["conclusion"] == "startup_failure":
            return self._block(
                state,
                "workflow-startup-failure",
                "explicit subject workflow attempt failed before jobs started",
            )
        source_blocker = self._source_attestation_blocker(
            state,
            controller_payload,
            selected,
        )
        if source_blocker:
            return self._block(state, *source_blocker)

        jobs_payload = self.api.list_run_jobs(
            repository,
            selected["id"],
            selected["run_attempt"],
        )
        jobs_blocker = _validate_jobs_envelope(jobs_payload, selected)
        if jobs_blocker:
            return self._block(state, *jobs_blocker)
        gate_blockers = _evaluate_gate_jobs(
            state,
            jobs_payload["jobs"],
            self.config.gate_jobs,
        )
        if gate_blockers:
            if rerun_failed and selected["conclusion"] not in {
                "success",
                "startup_failure",
            }:
                return self._block(
                    state,
                    "automatic-rerun-not-exact-attempt-safe",
                    (
                        "GitHub's run rerun endpoint does not accept an attempt; "
                        "automatic rerun is disabled to avoid a TOCTOU race"
                    ),
                )
            _set_blockers(state, gate_blockers)
            state["phase"] = "deterministic-blocked"
            return self._finish(state, persist=not state["dry_run"])

        if not self.config.latest_run_inventory_verified:
            return self._block(
                state,
                "latest-run-inventory-unverified",
                (
                    "no trusted complete inventory proves the explicit subject is "
                    "the newest same-repository pull-request/head run"
                ),
            )
        inventory_blocker = self._run_inventory_blocker(state, selected)
        if inventory_blocker:
            return self._block(state, *inventory_blocker)

        if not self.config.external_singleflight_verified:
            return self._block(
                state,
                "external-singleflight-unverified",
                (
                    "no GitHub-native or shared transactional coordinator proves "
                    "single-writer ownership across hosted runners"
                ),
            )

        if not self.config.invalidation_controller_verified:
            return self._block(
                state,
                "label-invalidation-controller-unverified",
                (
                    "no hosted readback proves an always-on controller removes "
                    "final labels after pull request lifecycle or head changes"
                ),
            )

        if not self.config.provider_contract_verified:
            return self._block(
                state,
                "provider-evidence-contract-unverified",
                "hosted CodeRabbit/Codex exact-head evidence has not passed a canary",
            )
        if not self.config.codex_hosted_canary_verified:
            return self._block(
                state,
                "codex-hosted-canary-unverified",
                "Codex native PASS semantics remain disabled until hosted canary evidence is supplied",
            )

        if _looks_like_dependabot(pull_payload):
            state["dependabot"] = {
                "eligible": True,
                "proof": "disabled",
            }
            return self._block(
                state,
                "dependabot-bypass-disabled",
                (
                    "Dependabot cannot bypass mandatory AI review because REST "
                    "actor and signature metadata are not unforgeable provenance"
                ),
            )

        promotion_result = self._promote_labels(state, FINAL_LABELS)
        if promotion_result is not None:
            return promotion_result
        return self._poll_providers(
            state,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )

    def _promote_labels(
        self,
        state: dict[str, Any],
        labels: tuple[str, ...],
    ) -> dict[str, Any] | None:
        repository = state["key"]["repository"]
        number = state["key"]["pull_request"]
        head_sha = state["key"]["head_sha"]
        try:
            self._read_boundary(
                repository,
                number,
                expected_head=head_sha,
                expected_repository_id=state["key"]["repository_id"],
                expected_base=state["base_sha"],
            )
            run_blocker = self._revalidate_run_blocker(state)
            if run_blocker:
                return self._block(state, *run_blocker)
            live_before = self.api.get_pull_labels(repository, number)
        except BoundaryViolation as exc:
            return self._block_after_label_rollback(
                state,
                exc.code,
                exc.detail,
            )
        except (GitHubAPIError, ProviderUnavailable) as exc:
            return self._block_after_label_rollback(
                state,
                "label-readback-unavailable",
                (f"label or provenance readback failed closed: {_bounded_failure_reason(exc)}"),
            )
        for label in labels:
            if label in live_before:
                state["labels"][label] = "applied"
        unapplied = tuple(label for label in labels if label not in live_before)
        if not unapplied:
            return None
        if state["dry_run"]:
            for label in unapplied:
                state["labels"][label] = "planned"
            return self._block(
                state,
                "dry-run-no-mutations",
                "labels were planned but dry-run forbids mutations",
                phase="dry-run",
                persist=False,
            )
        try:
            self.api.add_labels(repository, number, unapplied)
        except AmbiguousMutation:
            pass
        except (GitHubAPIError, ProviderUnavailable) as exc:
            return self._block_after_label_rollback(
                state,
                "label-write-rejected",
                f"label write failed closed: {type(exc).__name__}",
            )
        except Exception as exc:
            return self._block_after_label_rollback(
                state,
                "label-write-exception",
                f"unexpected label write exception: {type(exc).__name__}",
            )
        try:
            live_after = self.api.get_pull_labels(repository, number)
            if any(label not in live_after for label in labels):
                rollback_error = self._rollback_labels(state)
                if rollback_error:
                    _set_blockers(
                        state,
                        [
                            (
                                "label-write-not-confirmed",
                                "live readback did not contain the exact promoted label set",
                            ),
                            ("label-rollback-unconfirmed", rollback_error),
                        ],
                    )
                    state["phase"] = "blocked"
                    return self._finish(state, persist=True)
                return self._block(
                    state,
                    "label-write-not-confirmed",
                    "live readback did not contain the exact promoted label set",
                )
            self._read_boundary(
                repository,
                number,
                expected_head=head_sha,
                expected_repository_id=state["key"]["repository_id"],
                expected_base=state["base_sha"],
            )
            run_blocker = self._revalidate_run_blocker(state)
            if run_blocker:
                raise BoundaryViolation(*run_blocker)
        except (GitHubAPIError, ProviderUnavailable) as exc:
            rollback_error = self._rollback_labels(state)
            blockers = [
                (
                    "label-readback-unavailable",
                    f"label readback failed closed: {type(exc).__name__}",
                )
            ]
            if rollback_error:
                blockers.append(("label-rollback-unconfirmed", rollback_error))
            _set_blockers(state, blockers)
            state["phase"] = "blocked"
            return self._finish(state, persist=True)
        except BoundaryViolation as exc:
            rollback_error = self._rollback_labels(state)
            if rollback_error:
                _set_blockers(
                    state,
                    [
                        (exc.code, exc.detail),
                        (
                            "label-rollback-unconfirmed",
                            rollback_error,
                        ),
                    ],
                )
                state["phase"] = "blocked"
                return self._finish(state, persist=True)
            return self._block(state, exc.code, exc.detail)
        except Exception as exc:
            return self._block_after_label_rollback(
                state,
                "label-reconciliation-exception",
                f"unexpected post-write label exception: {type(exc).__name__}",
            )
        for label in unapplied:
            state["labels"][label] = "applied"
        state["phase"] = "awaiting-providers"
        return None

    def _revalidate_run_blocker(
        self,
        state: dict[str, Any],
    ) -> tuple[str, str] | None:
        controller_state = state["controller_run"]
        subject_state = state["subject_run"]
        workflow = self.config.workflow
        controller = self.config.controller
        subject_run_id = self.config.subject_run_id
        subject_run_attempt = self.config.subject_run_attempt
        if (
            not isinstance(controller_state, dict)
            or not isinstance(subject_state, dict)
            or workflow is None
            or controller is None
            or subject_run_id is None
            or subject_run_attempt is None
        ):
            return (
                "source-provenance-unavailable",
                "controller or subject workflow attempt is absent from the closed state",
            )
        repository = state["key"]["repository"]
        current_controller = self.api.get_workflow_run(
            repository,
            controller.run_id,
        )
        controller_blocker = _validate_controller_run_identity(
            current_controller,
            controller,
            workflow.promoter,
        )
        if controller_blocker:
            return controller_blocker
        if (
            current_controller.get("id") != controller_state["id"]
            or current_controller.get("run_attempt") != controller_state["attempt"]
        ):
            return (
                "controller-attempt-changed",
                "trusted controller run or attempt changed",
            )
        current_subject = self.api.get_workflow_run(
            repository,
            subject_run_id,
        )
        subject_blocker = _validate_subject_run_identity(
            current_subject,
            workflow,
            subject_run_id,
            subject_run_attempt,
            controller.ref,
        )
        if subject_blocker:
            return subject_blocker
        if (
            current_subject.get("id") != subject_state["id"]
            or current_subject.get("run_attempt") != subject_state["attempt"]
            or current_subject.get("status") != "completed"
            or current_subject.get("conclusion") != "success"
        ):
            return (
                "subject-attempt-changed",
                "selected subject attempt is no longer terminal and successful",
            )
        source_blocker = self._source_attestation_blocker(
            state,
            current_controller,
            current_subject,
        )
        if source_blocker:
            return source_blocker
        return self._run_inventory_blocker(state, current_subject)

    def _run_inventory_blocker(
        self,
        state: dict[str, Any],
        selected: dict[str, Any],
    ) -> tuple[str, str] | None:
        workflow = self.config.workflow
        if workflow is None:
            return (
                "latest-run-inventory-unverified",
                "immutable subject workflow identity is unavailable",
            )
        try:
            inventory = self.api.list_same_head_run_inventory(
                state["key"]["repository"],
                state["key"]["pull_request"],
                state["key"]["head_sha"],
                state["base_sha"],
                workflow.workflow_id,
                selected["id"],
                selected["run_attempt"],
                workflow.sha,
            )
        except (GitHubAPIError, ProviderUnavailable) as exc:
            return (
                "latest-run-inventory-unavailable",
                f"complete same-head run inventory failed: {_bounded_failure_reason(exc)}",
            )
        return _validate_same_head_run_inventory(
            inventory,
            state,
            selected,
            workflow,
        )

    def _source_attestation_blocker(
        self,
        state: dict[str, Any],
        controller_payload: dict[str, Any],
        selected: dict[str, Any],
    ) -> tuple[str, str] | None:
        repository = state["key"]["repository"]
        number = state["key"]["pull_request"]
        head_sha = state["key"]["head_sha"]
        controller_run_id = controller_payload["id"]
        controller_attempt = controller_payload["run_attempt"]
        subject_run_id = selected["id"]
        subject_attempt = selected["run_attempt"]
        try:
            attestation = self.api.get_run_source_attestation(
                repository,
                number,
                head_sha,
                state["base_sha"],
                controller_run_id,
                controller_attempt,
                subject_run_id,
                subject_attempt,
            )
        except (GitHubAPIError, ProviderUnavailable) as exc:
            return (
                "source-provenance-unavailable",
                (f"trusted source attestation readback failed: {_bounded_failure_reason(exc)}"),
            )
        return _validate_source_attestation(
            attestation,
            state,
            controller_payload,
            selected,
            self.config.workflow,
            self.config.controller,
        )

    def _rollback_labels(
        self,
        state: dict[str, Any],
    ) -> str | None:
        repository = state["key"]["repository"]
        number = state["key"]["pull_request"]

        def read_closed_labels() -> set[str]:
            self._read_boundary(
                repository,
                number,
                expected_head=state["key"]["head_sha"],
                expected_repository_id=state["key"]["repository_id"],
                expected_base=state["base_sha"],
            )
            return self.api.get_pull_labels(repository, number)

        try:
            for label in FINAL_LABELS:
                live = read_closed_labels()
                if label in live:
                    self.api.remove_label(repository, number, label)
            confirmed = read_closed_labels()
        except Exception as exc:
            detail = f"{exc.code}: {exc.detail}" if isinstance(exc, BoundaryViolation) else type(exc).__name__
            return f"could not reconcile final-label rollback: {detail}"
        remaining = [label for label in FINAL_LABELS if label in confirmed]
        if remaining:
            return f"final labels remained after rollback: {remaining!r}"
        return None

    def _block_after_label_rollback(
        self,
        state: dict[str, Any],
        code: str,
        detail: str,
        *,
        phase: str = "blocked",
    ) -> dict[str, Any]:
        blockers = [(code, detail)]
        if not state["dry_run"]:
            rollback_error = self._rollback_labels(state)
            if rollback_error:
                blockers.append(("label-rollback-unconfirmed", rollback_error))
            else:
                for label in FINAL_LABELS:
                    state["labels"][label] = "pending"
        _set_blockers(state, blockers)
        state["phase"] = phase
        state["complete"] = False
        return self._finish(state, persist=not state["dry_run"])

    def _poll_providers(
        self,
        state: dict[str, Any],
        *,
        timeout_seconds: int,
        poll_seconds: int,
    ) -> dict[str, Any]:
        repository = state["key"]["repository"]
        number = state["key"]["pull_request"]
        head_sha = state["key"]["head_sha"]
        deadline = self._monotonic() + timeout_seconds
        while True:
            try:
                self._read_boundary(
                    repository,
                    number,
                    expected_head=head_sha,
                    expected_repository_id=state["key"]["repository_id"],
                    expected_base=state["base_sha"],
                )
                run_blocker = self._revalidate_run_blocker(state)
                if run_blocker:
                    return self._block_after_label_rollback(
                        state,
                        *run_blocker,
                    )
                snapshot = self.api.provider_snapshot(repository, number, head_sha)
            except BoundaryViolation as exc:
                return self._block_after_label_rollback(
                    state,
                    exc.code,
                    exc.detail,
                )
            except (GitHubAPIError, ProviderUnavailable) as exc:
                reason = (
                    _bounded_failure_reason(exc) if isinstance(exc, ProviderUnavailable) else "malformed-api-readback"
                )
                code = {
                    "rate-limit": "provider-rate-limit",
                    "quota": "provider-quota-exhausted",
                    "outage": "provider-outage",
                    "malformed-api-readback": "provider-evidence-malformed",
                }.get(reason, "provider-unavailable")
                return self._block_after_label_rollback(
                    state,
                    code,
                    f"provider readback failed closed: {reason}",
                    phase="awaiting-providers",
                )

            statuses, blockers, pending = _evaluate_provider_snapshot(
                snapshot,
                head_sha,
                self.config.providers,
            )
            state["providers"].update(statuses)
            if not blockers:
                post_blocker: tuple[str, str] | None = None
                try:
                    self._read_boundary(
                        repository,
                        number,
                        expected_head=head_sha,
                        expected_repository_id=state["key"]["repository_id"],
                        expected_base=state["base_sha"],
                    )
                except BoundaryViolation as exc:
                    post_blocker = (exc.code, exc.detail)
                except (GitHubAPIError, ProviderUnavailable) as exc:
                    post_blocker = (
                        "final-provenance-readback-unavailable",
                        (f"final repository or pull-request readback failed closed: {_bounded_failure_reason(exc)}"),
                    )
                if post_blocker is None:
                    try:
                        post_blocker = self._revalidate_run_blocker(state)
                    except (GitHubAPIError, ProviderUnavailable) as exc:
                        post_blocker = (
                            "final-provenance-readback-unavailable",
                            (f"final provenance readback failed closed: {_bounded_failure_reason(exc)}"),
                        )
                if post_blocker is None:
                    try:
                        live_labels = self.api.get_pull_labels(repository, number)
                    except (GitHubAPIError, ProviderUnavailable) as exc:
                        post_blocker = (
                            "final-label-readback-unavailable",
                            f"final label readback failed closed: {type(exc).__name__}",
                        )
                    else:
                        missing = [label for label in FINAL_LABELS if label not in live_labels]
                        if missing:
                            post_blocker = (
                                "final-labels-missing",
                                f"final labels disappeared before completion: {missing!r}",
                            )
                if post_blocker:
                    return self._block_after_label_rollback(
                        state,
                        *post_blocker,
                    )
                state["complete"] = True
                state["phase"] = "complete"
                _set_blockers(state, [])
                return self._finish(state, persist=not state["dry_run"])
            if pending and self._monotonic() < deadline:
                self._sleep(min(poll_seconds, max(0.0, deadline - self._monotonic())))
                continue
            if pending and timeout_seconds > 0:
                blockers = [
                    (
                        "provider-timeout",
                        "bounded provider polling expired without closed PASS evidence",
                    )
                ]
            if not pending or timeout_seconds > 0:
                code, detail = blockers[0]
                result = self._block_after_label_rollback(
                    state,
                    code,
                    detail,
                    phase="awaiting-providers",
                )
                remaining = blockers[1:]
                if remaining:
                    combined = [(item["code"], item["detail"]) for item in result["blockers"]]
                    _set_blockers(result, [*combined, *remaining])
                    return self._finish(result, persist=not state["dry_run"])
                return result
            _set_blockers(state, blockers)
            state["phase"] = "awaiting-providers"
            return self._finish(state, persist=not state["dry_run"])

    def _read_boundary(
        self,
        repository: str,
        number: int,
        *,
        expected_head: str | None = None,
        expected_repository_id: int | None = None,
        expected_base: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        repository_payload = self.api.get_repository(repository)
        pull_payload = self.api.get_pull(repository, number)
        _validate_repository_and_pull(
            repository,
            number,
            repository_payload,
            pull_payload,
            expected_head=expected_head,
            expected_repository_id=expected_repository_id,
            expected_base=expected_base,
        )
        return repository_payload, pull_payload

    def _block(
        self,
        state: dict[str, Any],
        code: str,
        detail: str,
        *,
        phase: str = "blocked",
        persist: bool | None = None,
    ) -> dict[str, Any]:
        state["complete"] = False
        state["phase"] = phase
        _set_blockers(state, [(code, detail)])
        should_persist = not state["dry_run"] if persist is None else persist
        return self._finish(state, persist=should_persist)

    def _finish(self, state: dict[str, Any], *, persist: bool) -> dict[str, Any]:
        if (
            persist
            and not state["dry_run"]
            and state["phase"] in {"blocked", "deterministic-blocked"}
            and any(state["labels"][label] == "applied" for label in FINAL_LABELS)
        ):
            blockers = [(item["code"], item["detail"]) for item in state["blockers"]]
            rollback_error = self._rollback_labels(state)
            if rollback_error:
                if not any(code == "label-rollback-unconfirmed" for code, _ in blockers):
                    blockers.append(("label-rollback-unconfirmed", rollback_error))
            else:
                for label in FINAL_LABELS:
                    state["labels"][label] = "pending"
            _set_blockers(state, blockers)
        state["updated_at"] = self._timestamp()
        validate_state(state)
        if persist:
            try:
                self._save(state)
            except (StateConflictError, StatePersistenceError) as exc:
                blockers = [(item["code"], item["detail"]) for item in state["blockers"]]
                if isinstance(exc, StateConflictError):
                    blockers.append(
                        (
                            "state-write-conflict",
                            (
                                "exact-head state changed or is owned by another "
                                "writer; completion cannot be made durable"
                            ),
                        )
                    )
                else:
                    blockers.append(
                        (
                            "state-persistence-failed",
                            ("exact-head state could not be durably replaced; completion cannot be trusted"),
                        )
                    )
                if any(state["labels"][label] == "applied" for label in FINAL_LABELS):
                    rollback_error = self._rollback_labels(state)
                    if rollback_error:
                        blockers.append(("label-rollback-unconfirmed", rollback_error))
                    else:
                        for label in FINAL_LABELS:
                            state["labels"][label] = "pending"
                state["complete"] = False
                state["phase"] = "blocked"
                _set_blockers(state, blockers)
                state["updated_at"] = self._timestamp()
                validate_state(state)
        return state

    def _timestamp(self) -> str:
        return self._now().astimezone(UTC).isoformat().replace("+00:00", "Z")

    def _path(self, repository: str, number: int, head_sha: str) -> Path:
        owner, name = repository.lower().split("/", 1)
        return self.state_dir / f"{owner}__{name}__pr-{number}__{head_sha}.json"

    @staticmethod
    def _read_state_bytes(path: Path) -> bytes:
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_STATE_BYTES + 1)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise StatePersistenceError("exact-head state could not be read") from exc
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("finalizer state exceeds 1 MiB")
        return raw

    def _observe_state_path(self, path: Path) -> None:
        if path in self._expected_state_digests:
            return
        try:
            raw = self._read_state_bytes(path)
        except FileNotFoundError:
            digest = None
        else:
            digest = hashlib.sha256(raw).hexdigest()
        self._expected_state_digests[path] = digest

    def _load(self, repository: str, number: int, head_sha: str) -> dict[str, Any]:
        path = self._path(repository, number, head_sha)
        try:
            raw = self._read_state_bytes(path)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"no exact-head finalizer state at {path}") from exc
        try:
            state = cast(dict[str, Any], json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("finalizer state is malformed") from exc
        validate_state(state)
        key = state["key"]
        if (
            key["repository"].lower() != repository.lower()
            or key["pull_request"] != number
            or key["head_sha"] != head_sha
        ):
            raise ValueError("finalizer state key does not match requested exact head")
        self._expected_state_digests[path] = hashlib.sha256(raw).hexdigest()
        return state

    def _save(self, state: dict[str, Any]) -> None:
        validate_state(state)
        key = state["key"]
        path = self._path(
            key["repository"],
            key["pull_request"],
            key["head_sha"],
        )
        encoded = (json.dumps(state, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
        if len(encoded) > MAX_STATE_BYTES:
            raise ValueError("finalizer state exceeds 1 MiB")
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StatePersistenceError("exact-head state directory could not be created") from exc
        self._observe_state_path(path)
        expected_digest = self._expected_state_digests[path]
        lock_path = path.with_suffix(".json.lock")
        lock_token = f"{os.getpid()}:{os.urandom(16).hex()}\n".encode("ascii")
        lock_identity: tuple[int, int] | None = None
        temporary_path: Path | None = None
        temporary_identity: tuple[int, int] | None = None
        temporary_fd: int | None = None
        lock_fd: int | None = None
        lock_acquired = False
        try:
            lock_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                lock_flags |= os.O_BINARY
            try:
                lock_fd = os.open(lock_path, lock_flags, 0o600)
            except FileExistsError as exc:
                raise StateConflictError("exact-head writer lock already exists") from exc
            except OSError as exc:
                raise StatePersistenceError("exact-head writer lock could not be acquired") from exc
            lock_acquired = True
            lock_stat = os.fstat(lock_fd)
            lock_identity = (lock_stat.st_dev, lock_stat.st_ino)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(lock_fd, 0o600)
                owned_lock_fd = lock_fd
                lock_fd = None
                with os.fdopen(
                    owned_lock_fd,
                    "wb",
                    closefd=True,
                ) as lock_stream:
                    lock_stream.write(lock_token)
                    lock_stream.flush()
                    os.fsync(lock_stream.fileno())
            except OSError as exc:
                raise StatePersistenceError("exact-head writer lock could not be made durable") from exc

            try:
                current_raw = self._read_state_bytes(path)
            except FileNotFoundError:
                current_digest = None
            except ValueError as exc:
                raise StatePersistenceError("existing exact-head state exceeded the closed limit") from exc
            else:
                current_digest = hashlib.sha256(current_raw).hexdigest()
            if current_digest != expected_digest:
                raise StateConflictError("exact-head state changed after this writer observed it")

            try:
                temporary_fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{path.name}.",
                    suffix=".tmp",
                    dir=path.parent,
                )
                temporary_path = Path(temporary_name)
                temporary_stat = os.fstat(temporary_fd)
                temporary_identity = (
                    temporary_stat.st_dev,
                    temporary_stat.st_ino,
                )
                if hasattr(os, "fchmod"):
                    os.fchmod(temporary_fd, 0o600)
                with os.fdopen(
                    temporary_fd,
                    "wb",
                    closefd=True,
                ) as temporary_stream:
                    temporary_fd = None
                    temporary_stream.write(encoded)
                    temporary_stream.flush()
                    os.fsync(temporary_stream.fileno())
                os.replace(temporary_path, path)
                temporary_path = None
            except OSError as exc:
                raise StatePersistenceError("exact-head state could not be atomically replaced") from exc
            self._fsync_directory(path.parent)
            self._expected_state_digests[path] = hashlib.sha256(encoded).hexdigest()
        finally:
            if lock_fd is not None:
                with suppress(OSError):
                    os.close(lock_fd)
            if temporary_fd is not None:
                with suppress(OSError):
                    os.close(temporary_fd)
            if temporary_path is not None and temporary_identity is not None:
                self._unlink_owned_path(
                    temporary_path,
                    temporary_identity,
                )
            if (
                lock_acquired
                and lock_identity is not None
                and self._path_has_owned_token(
                    lock_path,
                    lock_identity,
                    lock_token,
                )
            ):
                self._unlink_owned_path(lock_path, lock_identity)

    @staticmethod
    def _path_has_owned_token(
        path: Path,
        expected_identity: tuple[int, int],
        token: bytes,
    ) -> bool:
        try:
            path_stat = path.lstat()
            if (path_stat.st_dev, path_stat.st_ino) != expected_identity:
                return False
            with path.open("rb") as stream:
                observed = stream.read(len(token) + 1)
        except OSError:
            return False
        return observed == token

    @staticmethod
    def _unlink_owned_path(
        path: Path,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            path_stat = path.lstat()
            if (path_stat.st_dev, path_stat.st_ino) != expected_identity:
                return
            path.unlink()
        except OSError:
            pass

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        directory_fd: int | None = None
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            directory_fd = os.open(path, flags)
            os.fsync(directory_fd)
        except OSError:
            pass
        finally:
            if directory_fd is not None:
                with suppress(OSError):
                    os.close(directory_fd)


def _external_json_is_bounded(value: Any) -> bool:
    """Validate a closed JSON-like value without materializing a second copy."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_EXTERNAL_NODES or depth > MAX_EXTERNAL_DEPTH:
            return False
        if current is None or type(current) in {bool, int, float}:
            continue
        if isinstance(current, str):
            if len(current) > MAX_EXTERNAL_STRING_CHARS:
                return False
            continue
        if isinstance(current, list):
            if len(current) > MAX_EXTERNAL_COLLECTION_ITEMS:
                return False
            identity = id(current)
            if identity in seen_containers:
                return False
            seen_containers.add(identity)
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if len(current) > MAX_EXTERNAL_COLLECTION_ITEMS:
                return False
            identity = id(current)
            if identity in seen_containers:
                return False
            seen_containers.add(identity)
            for key, item in current.items():
                if not isinstance(key, str) or len(key) > 256:
                    return False
                stack.append((item, depth + 1))
            continue
        return False
    return True


def _require_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubAPIError("GitHub API response was not an object")
    return value


def _validate_command_inputs(
    repository: str,
    number: int,
    timeout_seconds: int,
    poll_seconds: int,
) -> None:
    if (
        not isinstance(repository, str)
        or len(repository) > MAX_REPOSITORY_CHARS
        or not REPOSITORY_RE.fullmatch(repository)
    ):
        raise ValueError("repository must be OWNER/REPO")
    if type(number) is not int or number <= 0:
        raise ValueError("pull request number must be positive")
    if type(timeout_seconds) is not int or not 0 <= timeout_seconds <= MAX_POLL_SECONDS:
        raise ValueError(f"timeout must be between 0 and {MAX_POLL_SECONDS} seconds")
    if type(poll_seconds) is not int or not 1 <= poll_seconds <= MAX_POLL_INTERVAL_SECONDS:
        raise ValueError(f"poll interval must be between 1 and {MAX_POLL_INTERVAL_SECONDS} seconds")


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise ValueError(f"{name} must be a full lowercase commit SHA")
    return value


def _normalized_run_workflow_path(value: Any, default_branch: str) -> str:
    if not isinstance(value, str):
        raise GitHubAPIError("workflow run path is malformed")
    if WORKFLOW_PATH_RE.fullmatch(value):
        return value
    suffixes = (f"@{default_branch}", f"@refs/heads/{default_branch}")
    matching = [suffix for suffix in suffixes if value.endswith(suffix)]
    if len(matching) != 1:
        raise GitHubAPIError("workflow run path is not bound to the default branch")
    path = value[: -len(matching[0])]
    if not WORKFLOW_PATH_RE.fullmatch(path):
        raise GitHubAPIError("workflow run path is not normalized")
    return path


def _pull_head_sha(pull_payload: dict[str, Any]) -> str:
    try:
        value = pull_payload["head"]["sha"]
    except (KeyError, TypeError) as exc:
        raise BoundaryViolation(
            "pull-payload-invalid",
            "pull request head SHA is missing",
        ) from exc
    try:
        return _require_sha(value, "pull head")
    except ValueError as exc:
        raise BoundaryViolation("pull-payload-invalid", str(exc)) from exc


def _validate_repository_and_pull(
    repository: str,
    number: int,
    repository_payload: dict[str, Any],
    pull_payload: dict[str, Any],
    *,
    expected_head: str | None,
    expected_repository_id: int | None,
    expected_base: str | None,
) -> None:
    if not _external_json_is_bounded(repository_payload) or not _external_json_is_bounded(pull_payload):
        raise BoundaryViolation(
            "pull-payload-unbounded",
            "repository or pull request payload exceeded closed limits",
        )
    repository_id = repository_payload.get("id")
    repository_full_name = repository_payload.get("full_name")
    if (
        type(repository_id) is not int
        or not isinstance(repository_full_name, str)
        or repository_full_name.lower() != repository.lower()
    ):
        raise BoundaryViolation(
            "repository-identity-changed",
            "repository id or canonical full name does not match",
        )
    if expected_repository_id is not None and repository_id != expected_repository_id:
        raise BoundaryViolation(
            "repository-identity-changed",
            "repository id changed from the closed attempt",
        )
    if type(pull_payload.get("number")) is not int or pull_payload.get("number") != number:
        raise BoundaryViolation(
            "pull-identity-changed",
            "pull request number does not match",
        )
    if pull_payload.get("state") != "open" or pull_payload.get("draft") is not False:
        raise BoundaryViolation(
            "pull-not-open-ready",
            "pull request must remain open and non-draft",
        )
    default_branch = repository_payload.get("default_branch")
    base = pull_payload.get("base")
    head = pull_payload.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise BoundaryViolation("pull-payload-invalid", "pull base/head is malformed")
    base_repo = base.get("repo")
    head_repo = head.get("repo")
    if (
        base.get("ref") != default_branch
        or not isinstance(base_repo, dict)
        or base_repo.get("id") != repository_id
        or str(base_repo.get("full_name", "")).lower() != repository.lower()
    ):
        raise BoundaryViolation(
            "wrong-protected-base",
            "pull request no longer targets the repository default branch",
        )
    if (
        not isinstance(head_repo, dict)
        or head_repo.get("id") != repository_id
        or str(head_repo.get("full_name", "")).lower() != repository.lower()
    ):
        raise BoundaryViolation(
            "fork-head-forbidden",
            "finalization permits only same-repository pull request heads",
        )
    head_sha = _pull_head_sha(pull_payload)
    try:
        base_sha = _require_sha(base.get("sha"), "base")
    except ValueError as exc:
        raise BoundaryViolation("pull-payload-invalid", str(exc)) from exc
    if expected_head is not None and head_sha != expected_head:
        raise BoundaryViolation(
            "pull-head-changed",
            "pull request head changed from the closed attempt",
        )
    if expected_base is not None and base_sha != expected_base:
        raise BoundaryViolation(
            "pull-base-changed",
            "pull request base changed from the closed attempt",
        )


def _select_run(
    runs: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, tuple[str, str] | None]:
    if not isinstance(runs, list) or not all(isinstance(item, dict) for item in runs):
        return None, ("workflow-runs-malformed", "workflow runs payload is malformed")
    if len(runs) > 100:
        return None, ("workflow-runs-unbounded", "workflow runs exceeded the closed limit")
    seen: set[tuple[Any, Any]] = set()
    for item in runs:
        run_id = item.get("id")
        attempt = item.get("run_attempt")
        if (
            type(run_id) is not int
            or run_id <= 0
            or type(attempt) is not int
            or attempt <= 0
            or not _valid_api_timestamp(item.get("created_at"))
            or not _valid_api_timestamp(item.get("updated_at"))
        ):
            return None, (
                "workflow-runs-malformed",
                "workflow run ordering or identity fields are malformed",
            )
        key = (item.get("id"), item.get("run_attempt"))
        if key in seen:
            return None, (
                "duplicate-run-attempt",
                "duplicate workflow run/attempt entries were returned",
            )
        seen.add(key)
    if not runs:
        return None, None

    def ordering(item: dict[str, Any]) -> tuple[str, int, int]:
        created = item.get("created_at")
        attempt_value = item.get("run_attempt")
        run_id_value = item.get("id")
        return (
            created if isinstance(created, str) else "",
            attempt_value if isinstance(attempt_value, int) else -1,
            run_id_value if isinstance(run_id_value, int) else -1,
        )

    return max(runs, key=ordering), None


def _valid_api_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_controller_boundary(
    controller: ControllerIdentity,
    repository_payload: dict[str, Any],
    repository: str,
) -> tuple[str, str] | None:
    default_branch = repository_payload.get("default_branch")
    expected_ref = f"refs/heads/{default_branch}" if isinstance(default_branch, str) and default_branch else None
    if controller.repository.lower() != repository.lower() or controller.repository_id != repository_payload.get("id"):
        return (
            "controller-repository-mismatch",
            "current controller repository identity does not match the target",
        )
    if expected_ref is None or controller.ref != expected_ref:
        return (
            "controller-not-default-branch",
            "current controller run is not bound to the repository default branch",
        )
    return None


def _validate_controller_run_identity(
    run_payload: dict[str, Any],
    controller: ControllerIdentity,
    promoter: Mapping[str, Any],
) -> tuple[str, str] | None:
    if not _external_json_is_bounded(run_payload):
        return (
            "controller-payload-unbounded",
            "controller run payload exceeded closed limits",
        )
    branch = controller.ref.removeprefix("refs/heads/")
    accepted_paths = {
        controller.path,
        f"{controller.path}@{branch}",
        f"{controller.path}@{controller.ref}",
    }
    workflow_id = run_payload.get("workflow_id")
    if (
        type(run_payload.get("id")) is not int
        or type(run_payload.get("run_attempt")) is not int
        or type(workflow_id) is not int
        or workflow_id <= 0
        or run_payload.get("path") not in accepted_paths
        or run_payload.get("event") != controller.event
    ):
        return (
            "wrong-controller-identity",
            "current controller workflow id, path, or event does not match",
        )
    if run_payload.get("head_sha") != controller.sha or run_payload.get("head_branch") != branch:
        return (
            "wrong-controller-head",
            "current run is not bound to the trusted default-branch controller",
        )
    if run_payload.get("id") != controller.run_id or run_payload.get("run_attempt") != controller.run_attempt:
        return (
            "wrong-controller-run-attempt",
            "workflow run is not the current trusted controller attempt",
        )
    status = run_payload.get("status")
    conclusion = run_payload.get("conclusion")
    if status == "in_progress":
        if conclusion is not None:
            return (
                "controller-state-invalid",
                "in-progress controller run unexpectedly has a conclusion",
            )
    elif status == "completed":
        if conclusion != "success":
            return (
                "controller-state-invalid",
                "completed controller run is not successful",
            )
    else:
        return (
            "controller-state-invalid",
            "controller must be in progress or successfully completed",
        )
    expected_actor = _actor_projection(promoter)
    if (
        _actor_projection(run_payload.get("actor")) != expected_actor
        or _actor_projection(run_payload.get("triggering_actor")) != expected_actor
    ):
        return (
            "wrong-controller-promoter",
            "controller run was not created by the closed promoter identity",
        )
    return None


def _validate_subject_run_identity(
    run_payload: dict[str, Any],
    workflow: WorkflowIdentity | None,
    subject_run_id: int,
    subject_run_attempt: int,
    controller_ref: str,
) -> tuple[str, str] | None:
    if not _external_json_is_bounded(run_payload):
        return (
            "subject-payload-unbounded",
            "subject run payload exceeded closed limits",
        )
    if workflow is None:
        return (
            "workflow-identity-unconfigured",
            "immutable subject workflow identity is not configured",
        )
    branch = controller_ref.removeprefix("refs/heads/")
    accepted_paths = {
        workflow.path,
        f"{workflow.path}@{branch}",
        f"{workflow.path}@{controller_ref}",
    }
    if type(run_payload.get("id")) is not int or type(run_payload.get("run_attempt")) is not int:
        return (
            "wrong-subject-run-attempt",
            "subject run id or attempt is malformed",
        )
    if (
        run_payload.get("workflow_id") != workflow.workflow_id
        or run_payload.get("path") not in accepted_paths
        or run_payload.get("event") != workflow.event
    ):
        return (
            "wrong-workflow-identity",
            "subject workflow id, path, or event does not match",
        )
    try:
        _require_sha(run_payload.get("head_sha"), "subject controller head")
    except ValueError:
        return (
            "wrong-subject-head",
            "subject run controller head is malformed",
        )
    if run_payload.get("head_branch") != branch:
        return (
            "wrong-subject-head",
            "subject run is not bound to the repository default branch",
        )
    if run_payload.get("id") != subject_run_id or run_payload.get("run_attempt") != subject_run_attempt:
        return (
            "wrong-subject-run-attempt",
            "workflow run is not the explicit subject attempt",
        )
    referenced = run_payload.get("referenced_workflows")
    if not isinstance(referenced, list) or len(referenced) > 20:
        return (
            "wrong-workflow-identity",
            "referenced workflow provenance is absent or unbounded",
        )
    matching = [item for item in referenced if isinstance(item, dict) and item.get("path") == workflow.source_path]
    if len(matching) != 1:
        return (
            "wrong-workflow-identity",
            "immutable referenced workflow path, SHA, or ref does not match",
        )
    referenced_workflow = matching[0]
    referenced_ref = referenced_workflow.get("ref")
    if referenced_workflow.get("sha") != workflow.sha or referenced_ref not in {None, workflow.sha}:
        return (
            "wrong-workflow-identity",
            "immutable referenced workflow path, SHA, or ref does not match",
        )
    expected_actor = _actor_projection(workflow.promoter)
    if (
        _actor_projection(run_payload.get("actor")) != expected_actor
        or _actor_projection(run_payload.get("triggering_actor")) != expected_actor
    ):
        return (
            "wrong-workflow-promoter",
            "subject workflow_dispatch run was not created by the closed promoter identity",
        )
    return None


def _actor_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    login = value.get("login")
    actor_id = value.get("id")
    actor_type = value.get("type")
    if (
        not isinstance(login, str)
        or not login
        or len(login) > 256
        or type(actor_id) is not int
        or actor_id <= 0
        or actor_type not in {"Bot", "User"}
    ):
        return None
    return {"login": login, "id": actor_id, "type": actor_type}


def _validate_source_attestation(
    attestation: Any,
    state: dict[str, Any],
    controller_payload: dict[str, Any],
    selected: dict[str, Any],
    workflow: WorkflowIdentity | None,
    controller: ControllerIdentity | None,
) -> tuple[str, str] | None:
    if workflow is None or controller is None:
        return (
            "source-provenance-unavailable",
            "immutable workflow identity is not configured",
        )
    if (
        controller_payload.get("head_sha") != state["base_sha"]
        or selected.get("head_sha") != state["base_sha"]
        or controller.sha != state["base_sha"]
    ):
        return (
            "source-provenance-invalid",
            "controller and subject source commits are not the exact pull-request base",
        )
    if (
        not isinstance(attestation, dict)
        or not _external_json_is_bounded(attestation)
        or attestation.get("readback") != "complete"
    ):
        return (
            "source-provenance-unavailable",
            (
                "trusted same-run source attestation is unavailable; local state "
                "and workflow-run discovery are non-authoritative"
            ),
        )
    expected = {
        "readback": "complete",
        "schema_version": "koios-run-source-v3",
        "repository_id": state["key"]["repository_id"],
        "pull_request": state["key"]["pull_request"],
        "pr_head_sha": state["key"]["head_sha"],
        "base_sha": state["base_sha"],
        "controller_run_id": controller_payload["id"],
        "controller_run_attempt": controller_payload["run_attempt"],
        "controller_workflow_id": controller_payload["workflow_id"],
        "controller_path": controller.path,
        "controller_sha": controller.sha,
        "controller_ref": controller.ref,
        "controller_event": controller.event,
        "subject_run_id": selected["id"],
        "subject_run_attempt": selected["run_attempt"],
        "subject_workflow_id": workflow.workflow_id,
        "subject_path": workflow.path,
        "subject_sha": selected["head_sha"],
        "authored_source_selector": workflow.source_path,
        "resolved_source_sha": workflow.sha,
        "source_path": workflow.source_path,
        "source_sha": workflow.sha,
        "promoter": _actor_projection(workflow.promoter),
    }
    normalized = dict(attestation)
    normalized["promoter"] = _actor_projection(attestation.get("promoter"))
    try:
        normalized_json = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
        )
        expected_json = json.dumps(
            expected,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        normalized_json = ""
        expected_json = "invalid"
    if normalized_json != expected_json:
        return (
            "source-provenance-invalid",
            ("source attestation is not exactly bound to repo/PR/head/controller/subject/source"),
        )
    return None


def _validate_jobs_envelope(
    payload: dict[str, Any],
    selected: dict[str, Any],
) -> tuple[str, str] | None:
    if not isinstance(payload, dict) or not _external_json_is_bounded(payload):
        return ("workflow-jobs-malformed", "workflow jobs payload is not an object")
    if payload.get("run_id") != selected["id"] or payload.get("run_attempt") != selected["run_attempt"]:
        return (
            "wrong-job-attempt",
            "job evidence is not from the selected exact workflow attempt",
        )
    rows = payload.get("jobs")
    total = payload.get("total_count")
    if not isinstance(rows, list) or type(total) is not int or total != len(rows):
        return (
            "workflow-jobs-malformed",
            "workflow job count or rows are malformed",
        )
    if total == 0:
        return (
            "workflow-zero-jobs",
            "workflow attempt created zero jobs and is not recovery evidence",
        )
    if total > 100:
        return ("workflow-jobs-unbounded", "workflow job count exceeded 100")
    if not all(isinstance(item, dict) for item in rows):
        return ("workflow-jobs-malformed", "workflow job row is malformed")
    return None


def _validate_same_head_run_inventory(
    payload: Any,
    state: dict[str, Any],
    selected: dict[str, Any],
    workflow: WorkflowIdentity,
) -> tuple[str, str] | None:
    expected_fields = {
        "readback",
        "repository_id",
        "pull_request",
        "head_sha",
        "base_sha",
        "workflow_id",
        "selected_run_id",
        "selected_attempt",
        "platform_sha",
        "runs",
    }
    if (
        not isinstance(payload, dict)
        or not _external_json_is_bounded(payload)
        or set(payload) != expected_fields
        or payload.get("readback") != "complete"
        or payload.get("repository_id") != state["key"]["repository_id"]
        or payload.get("pull_request") != state["key"]["pull_request"]
        or payload.get("head_sha") != state["key"]["head_sha"]
        or payload.get("base_sha") != state["base_sha"]
        or payload.get("workflow_id") != workflow.workflow_id
        or payload.get("selected_run_id") != selected.get("id")
        or payload.get("selected_attempt") != selected.get("run_attempt")
        or payload.get("platform_sha") != workflow.sha
    ):
        return (
            "latest-run-inventory-invalid",
            "complete same-head run inventory binding is malformed or stale",
        )
    rows = payload.get("runs")
    if not isinstance(rows, list) or not rows or len(rows) > 1000:
        return (
            "latest-run-inventory-invalid",
            "same-head run inventory is empty or unbounded",
        )
    expected_title = (
        f"{FINAL_SUBJECT_RUN_NAME}|repo={state['key']['repository_id']}"
        f"|pr={state['key']['pull_request']}|head={state['key']['head_sha']}"
        f"|base={state['base_sha']}|platform={workflow.sha}"
    )
    row_fields = {
        "id",
        "attempt",
        "workflow_id",
        "display_title",
        "status",
        "conclusion",
        "created_at",
        "updated_at",
        "total_jobs",
    }
    allowed_statuses = {"queued", "in_progress", "completed", "pending", "waiting"}
    allowed_conclusions = {
        None,
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
    seen: set[tuple[int, int]] = set()
    normalized: list[tuple[datetime, int, int, dict[str, Any]]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != row_fields:
            return (
                "latest-run-inventory-invalid",
                "same-head run inventory contains a malformed row",
            )
        run_id = row.get("id")
        attempt = row.get("attempt")
        total_jobs = row.get("total_jobs")
        if (
            type(run_id) is not int
            or run_id <= 0
            or type(attempt) is not int
            or attempt <= 0
            or (run_id, attempt) in seen
            or row.get("workflow_id") != workflow.workflow_id
            or row.get("display_title") != expected_title
            or row.get("status") not in allowed_statuses
            or row.get("conclusion") not in allowed_conclusions
            or type(total_jobs) is not int
            or total_jobs < 0
            or not _valid_api_timestamp(row.get("created_at"))
            or not _valid_api_timestamp(row.get("updated_at"))
        ):
            return (
                "latest-run-inventory-invalid",
                "same-head run inventory identity, state, or attempt is invalid",
            )
        seen.add((run_id, attempt))
        created = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
        normalized.append((created, run_id, attempt, row))
    selected_key = (selected.get("id"), selected.get("run_attempt"))
    selected_rows = [item for item in normalized if (item[1], item[2]) == selected_key]
    if len(selected_rows) != 1 or selected_rows[0][3]["total_jobs"] <= 0:
        return (
            "latest-run-inventory-invalid",
            "selected exact attempt is absent, duplicated, or has zero jobs in the complete inventory",
        )
    selected_order = selected_rows[0][:3]
    newer = [item for item in normalized if item[:3] > selected_order]
    if newer:
        newest = max(newer, key=lambda item: item[:3])[3]
        return (
            "newer-same-head-run-attempt",
            (
                "a newer same-PR/head workflow attempt exists: "
                f"run={newest['id']} attempt={newest['attempt']} "
                f"status={newest['status']} conclusion={newest['conclusion']} "
                f"jobs={newest['total_jobs']}"
            ),
        )
    return None


def _evaluate_gate_jobs(
    state: dict[str, Any],
    rows: list[dict[str, Any]],
    gate_jobs: Mapping[str, str],
) -> list[tuple[str, str]]:
    blockers: list[tuple[str, str]] = []
    for gate, job_name in gate_jobs.items():
        matching = [
            item
            for item in rows
            if isinstance(item.get("name"), str)
            and (item["name"] == job_name or item["name"].endswith(f" / {job_name}"))
        ]
        if len(matching) != 1:
            state["gates"][gate] = "blocked"
            blockers.append(
                (
                    f"{gate}-job-ambiguous",
                    (
                        f"expected exactly one {job_name!r} job, optionally with GitHub's "
                        "caller prefix, in the exact attempt"
                    ),
                )
            )
            continue
        job = matching[0]
        if job.get("status") == "completed" and job.get("conclusion") == "success":
            state["gates"][gate] = "passed"
        else:
            state["gates"][gate] = "failed"
            blockers.append(
                (
                    f"{gate}-gate-failed",
                    f"{job_name!r} did not complete successfully",
                )
            )
    return blockers


def _looks_like_dependabot(pull_payload: dict[str, Any]) -> bool:
    user = pull_payload.get("user")
    return isinstance(user, dict) and str(user.get("login", "")).lower() == DEPENDABOT_LOGIN


def _parse_provider_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _latest_provider_item(
    items: list[dict[str, Any]],
    timestamp_key: str,
) -> tuple[dict[str, Any] | None, bool]:
    """Select a provider row only from unique positive IDs and aware timestamps."""

    if not items:
        return None, False
    ordered: list[tuple[datetime, int, dict[str, Any]]] = []
    seen_ids: set[int] = set()
    for item in items:
        item_id = item.get("id")
        timestamp = _parse_provider_timestamp(item.get(timestamp_key))
        if (
            isinstance(item_id, bool)
            or not isinstance(item_id, int)
            or item_id <= 0
            or item_id in seen_ids
            or timestamp is None
        ):
            return None, True
        seen_ids.add(item_id)
        ordered.append((timestamp, item_id, item))
    return max(ordered, key=lambda candidate: (candidate[0], candidate[1]))[2], False


def _evaluate_provider_snapshot(
    snapshot: dict[str, Any],
    head_sha: str,
    providers: tuple[ProviderIdentity, ...],
) -> tuple[dict[str, str], list[tuple[str, str]], bool]:
    statuses = {provider.name: "blocked" for provider in providers}
    if not _external_json_is_bounded(snapshot):
        return (
            statuses,
            [("provider-evidence-unbounded", "provider evidence exceeded closed limits")],
            False,
        )
    if not isinstance(snapshot, dict) or snapshot.get("readback") != "complete":
        return (
            statuses,
            [
                (
                    "provider-evidence-readback-incomplete",
                    "provider evidence does not prove complete review-thread resolution",
                )
            ],
            False,
        )
    expected_snapshot_fields = {
        "readback",
        "reviews",
        "issue_comments",
        "review_comments",
        "checks",
        "threads",
    }
    if set(snapshot) != expected_snapshot_fields:
        return (
            statuses,
            [("provider-evidence-malformed", "provider evidence snapshot is malformed")],
            False,
        )
    collection_names = ("reviews", "issue_comments", "review_comments", "checks")
    if any(not isinstance(snapshot.get(name), list) for name in collection_names):
        return (
            statuses,
            [("provider-evidence-malformed", "provider evidence snapshot is malformed")],
            False,
        )
    if any(any(not isinstance(item, dict) for item in snapshot[name]) for name in collection_names):
        return (
            statuses,
            [("provider-evidence-malformed", "provider evidence collection contains a malformed row")],
            False,
        )
    if any(len(snapshot[name]) > 1000 for name in collection_names):
        return (
            statuses,
            [("provider-evidence-unbounded", "provider evidence exceeded closed limits")],
            False,
        )
    threads_connection = snapshot["threads"]
    if (
        not isinstance(threads_connection, dict)
        or set(threads_connection) != {"nodes", "pageInfo"}
        or not isinstance(threads_connection["nodes"], list)
        or len(threads_connection["nodes"]) > 1000
    ):
        return (
            statuses,
            [("provider-evidence-malformed", "reviewThreads connection is malformed")],
            False,
        )
    threads_page_info = threads_connection["pageInfo"]
    if (
        not isinstance(threads_page_info, dict)
        or set(threads_page_info) != {"hasNextPage", "endCursor"}
        or not isinstance(threads_page_info["hasNextPage"], bool)
        or (threads_page_info["endCursor"] is not None and not isinstance(threads_page_info["endCursor"], str))
    ):
        return (
            statuses,
            [("provider-evidence-malformed", "reviewThreads pageInfo is malformed")],
            False,
        )
    if threads_page_info["hasNextPage"]:
        return (
            statuses,
            [
                (
                    "provider-evidence-readback-incomplete",
                    "reviewThreads collection was paginated",
                )
            ],
            False,
        )
    threads = threads_connection["nodes"]
    provider_logins = {provider.login for provider in providers}
    for thread in threads:
        if (
            not isinstance(thread, dict)
            or set(thread) != {"isResolved", "comments"}
            or not isinstance(thread["isResolved"], bool)
        ):
            return (
                statuses,
                [("provider-evidence-malformed", "review thread is malformed")],
                False,
            )
        comments = thread["comments"]
        if (
            not isinstance(comments, dict)
            or set(comments) != {"nodes", "pageInfo"}
            or not isinstance(comments["nodes"], list)
            or len(comments["nodes"]) > 1000
        ):
            return (
                statuses,
                [
                    (
                        "provider-evidence-malformed",
                        "review-thread comments are not a closed collection",
                    )
                ],
                False,
            )
        page_info = comments["pageInfo"]
        if (
            not isinstance(page_info, dict)
            or set(page_info) != {"hasNextPage", "endCursor"}
            or not isinstance(page_info["hasNextPage"], bool)
            or (page_info["endCursor"] is not None and not isinstance(page_info["endCursor"], str))
        ):
            return (
                statuses,
                [
                    (
                        "provider-evidence-malformed",
                        "review-thread pageInfo is not closed",
                    )
                ],
                False,
            )
        if page_info["hasNextPage"]:
            return (
                statuses,
                [
                    (
                        "provider-evidence-readback-incomplete",
                        "review-thread comments were paginated",
                    )
                ],
                False,
            )
        nodes = comments["nodes"]
        if any(
            not isinstance(node, dict)
            or set(node) != {"author"}
            or not isinstance(node["author"], dict)
            or set(node["author"]) != {"login"}
            or not isinstance(node["author"]["login"], str)
            or not node["author"]["login"]
            for node in nodes
        ):
            return (
                statuses,
                [
                    (
                        "provider-evidence-malformed",
                        "review-thread comment identity is malformed",
                    )
                ],
                False,
            )
        if thread["isResolved"] is False and any(node["author"]["login"] in provider_logins for node in nodes):
            return (
                statuses,
                [
                    (
                        "unresolved-review-threads",
                        "a CodeRabbit or Codex review thread remains unresolved",
                    )
                ],
                False,
            )

    blockers: list[tuple[str, str]] = []
    pending = False
    all_comments = [*snapshot["issue_comments"], *snapshot["review_comments"]]
    for provider in providers:
        provider_reviews = [
            item
            for item in snapshot["reviews"]
            if isinstance(item, dict)
            and isinstance(item.get("user"), dict)
            and item["user"].get("login") == provider.login
        ]
        provider_deliveries = [
            item
            for item in all_comments
            if isinstance(item, dict)
            and isinstance(item.get("user"), dict)
            and item["user"].get("login") == provider.login
        ]
        provider_checks = [
            item
            for item in snapshot["checks"]
            if provider.check_name is not None and item.get("name") == provider.check_name
        ]
        latest_review, review_ordering_invalid = _latest_provider_item(provider_reviews, "submitted_at")
        latest_delivery, delivery_ordering_invalid = _latest_provider_item(provider_deliveries, "updated_at")
        check_rows = [
            {
                **item,
                "ordering_at": item.get("completed_at") or item.get("started_at"),
            }
            for item in provider_checks
        ]
        latest_check, check_ordering_invalid = _latest_provider_item(check_rows, "ordering_at")
        if review_ordering_invalid or delivery_ordering_invalid or check_ordering_invalid:
            statuses[provider.name] = "blocked"
            blockers.append(
                (
                    "provider-evidence-malformed",
                    f"{provider.name} evidence has invalid or duplicate ordering identity",
                )
            )
            continue
        if (
            latest_review is None
            or latest_delivery is None
            or (provider.check_name is not None and latest_check is None)
        ):
            statuses[provider.name] = "pending"
            blockers.append(
                (
                    f"{provider.name}-evidence-pending",
                    f"{provider.name} exact-head native review, App delivery, or required check is absent",
                )
            )
            pending = True
            continue
        if latest_check is not None:
            native_output = latest_check.get("output")
            if (
                not isinstance(native_output, dict)
                or not {"title", "summary", "text"} <= set(native_output)
                or any(
                    value is not None and (not isinstance(value, str) or len(value) > MAX_EXTERNAL_STRING_CHARS)
                    for value in (native_output.get("title"), native_output.get("summary"), native_output.get("text"))
                )
            ):
                statuses[provider.name] = "blocked"
                blockers.append(
                    (
                        "provider-evidence-malformed",
                        f"{provider.name} native check output is malformed",
                    )
                )
                continue
        review_body = latest_review.get("body")
        delivery_body = latest_delivery.get("body")
        if (
            not isinstance(review_body, str)
            or len(review_body) > MAX_EXTERNAL_STRING_CHARS
            or not isinstance(delivery_body, str)
            or len(delivery_body) > MAX_EXTERNAL_STRING_CHARS
        ):
            statuses[provider.name] = "blocked"
            blockers.append(
                (
                    "provider-evidence-malformed",
                    f"{provider.name} review or App-delivery body is malformed or unbounded",
                )
            )
            continue
        evidence_text: list[str] = [review_body, delivery_body]
        if latest_check is not None:
            output = latest_check.get("output")
            if isinstance(output, dict):
                evidence_text.extend(str(output.get(field, "")) for field in ("title", "summary", "text"))
        current_bodies = " ".join(evidence_text).lower()
        marker = next(
            (item for item in PROVIDER_FAILURE_MARKERS if item in current_bodies),
            None,
        )
        if marker:
            code = (
                "provider-rate-limit"
                if "rate" in marker
                else "provider-quota-exhausted"
                if any(value in marker for value in ("quota", "credit", "usage"))
                else "provider-outage"
            )
            blockers.append((code, f"{provider.name} reported {marker!r}"))
            statuses[provider.name] = "blocked"
            continue
        app = latest_delivery.get("performed_via_github_app")
        review_time = _parse_provider_timestamp(latest_review.get("submitted_at"))
        delivery_time = _parse_provider_timestamp(latest_delivery.get("updated_at"))
        explicit_result_valid = provider.name != "codex" or (
            isinstance(review_body, str) and review_body.strip() == "PASS"
        )
        review_valid = (
            latest_review.get("commit_id") == head_sha
            and latest_review.get("state")
            in {
                "COMMENTED",
                "APPROVED",
            }
            and isinstance(review_body, str)
            and len(review_body) <= MAX_EXTERNAL_STRING_CHARS
            and explicit_result_valid
        )
        delivery_valid = (
            isinstance(app, dict)
            and app.get("id") == provider.app_id
            and app.get("slug") == provider.app_slug
            and isinstance(delivery_body, str)
            and len(delivery_body) <= MAX_EXTERNAL_STRING_CHARS
            and review_time is not None
            and delivery_time is not None
            and delivery_time >= review_time
        )
        check_valid = True
        if provider.check_name is not None:
            check_app = latest_check.get("app") if latest_check is not None else None
            check_valid = (
                latest_check is not None
                and latest_check.get("head_sha") == head_sha
                and latest_check.get("status") == "completed"
                and latest_check.get("conclusion") == "success"
                and isinstance(check_app, dict)
                and check_app.get("id") == provider.app_id
                and check_app.get("slug") == provider.app_slug
            )
        if not review_valid or not delivery_valid or not check_valid:
            statuses[provider.name] = "blocked"
            blockers.append(
                (
                    f"{provider.name}-evidence-invalid",
                    (
                        f"{provider.name} did not provide a current native review, "
                        "App-owned delivery, and successful provider check"
                    ),
                )
            )
            continue
        statuses[provider.name] = "passed"
    return statuses, blockers, pending


def _set_blockers(
    state: dict[str, Any],
    blockers: list[tuple[str, str]],
) -> None:
    unique: dict[str, str] = {}
    for code, detail in blockers:
        unique.setdefault(code, detail)
    state["blockers"] = [{"code": code, "detail": detail} for code, detail in sorted(unique.items())]


def validate_state(state: Any) -> None:
    if not isinstance(state, dict):
        raise ValueError("state must be an object")
    unexpected = set(state) - TOP_LEVEL_STATE_FIELDS
    missing = TOP_LEVEL_STATE_FIELDS - set(state)
    if unexpected:
        raise ValueError(f"unexpected state fields: {sorted(unexpected)}")
    if missing:
        raise ValueError(f"missing state fields: {sorted(missing)}")
    if state["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected state schema version")
    key = state["key"]
    if not isinstance(key, dict) or set(key) != {
        "repository",
        "repository_id",
        "pull_request",
        "head_sha",
    }:
        raise ValueError("state key is not closed")
    _validate_command_inputs(key["repository"], key["pull_request"], 0, 1)
    if type(key["repository_id"]) is not int or key["repository_id"] <= 0:
        raise ValueError("state repository id is invalid")
    _require_sha(key["head_sha"], "state head")
    _require_sha(state["base_sha"], "state base")
    if state["phase"] not in {
        "created",
        "blocked",
        "deterministic-blocked",
        "awaiting-providers",
        "dry-run",
        "complete",
    }:
        raise ValueError("state phase is invalid")
    if not isinstance(state["dry_run"], bool) or not isinstance(state["complete"], bool):
        raise ValueError("state booleans are invalid")
    workflow = state["workflow"]
    if workflow is not None and (
        not isinstance(workflow, dict)
        or set(workflow)
        != {
            "id",
            "path",
            "sha",
            "event",
            "source_path",
            "promoter",
        }
    ):
        raise ValueError("state workflow identity is not closed")
    if workflow is not None:
        try:
            WorkflowIdentity(
                workflow_id=workflow["id"],
                path=workflow["path"],
                sha=workflow["sha"],
                event=workflow["event"],
                source_path=workflow["source_path"],
                promoter=workflow["promoter"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("state workflow identity is invalid") from exc
    controller_run = state["controller_run"]
    controller_run_fields = {
        "id",
        "attempt",
        "workflow_id",
        "path",
        "sha",
        "ref",
        "status",
        "conclusion",
    }
    if controller_run is not None and (
        not isinstance(controller_run, dict) or set(controller_run) != controller_run_fields
    ):
        raise ValueError("state controller run identity is not closed")
    if controller_run is not None and (
        type(controller_run["id"]) is not int
        or controller_run["id"] <= 0
        or type(controller_run["attempt"]) is not int
        or controller_run["attempt"] <= 0
        or type(controller_run["workflow_id"]) is not int
        or controller_run["workflow_id"] <= 0
        or not isinstance(controller_run["path"], str)
        or len(controller_run["path"]) > 520
        or not RUN_PATH_RE.fullmatch(controller_run["path"])
        or ".." in controller_run["path"]
        or "//" in controller_run["path"]
        or not isinstance(controller_run["ref"], str)
        or len(controller_run["ref"]) > 256
        or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", controller_run["ref"])
        or ".." in controller_run["ref"]
        or "//" in controller_run["ref"]
        or not isinstance(controller_run["status"], str)
        or not controller_run["status"]
        or len(controller_run["status"]) > 64
        or (
            controller_run["conclusion"] is not None
            and (not isinstance(controller_run["conclusion"], str) or len(controller_run["conclusion"]) > 64)
        )
    ):
        raise ValueError("state controller run identity is invalid")
    if controller_run is not None:
        _require_sha(controller_run["sha"], "state controller head")
    subject_run = state["subject_run"]
    subject_run_fields = {
        "id",
        "attempt",
        "workflow_id",
        "path",
        "sha",
        "status",
        "conclusion",
    }
    if subject_run is not None and (not isinstance(subject_run, dict) or set(subject_run) != subject_run_fields):
        raise ValueError("state subject run identity is not closed")
    if subject_run is not None and (
        type(subject_run["id"]) is not int
        or subject_run["id"] <= 0
        or type(subject_run["attempt"]) is not int
        or subject_run["attempt"] <= 0
        or type(subject_run["workflow_id"]) is not int
        or subject_run["workflow_id"] <= 0
        or not isinstance(subject_run["path"], str)
        or len(subject_run["path"]) > 520
        or not RUN_PATH_RE.fullmatch(subject_run["path"])
        or ".." in subject_run["path"]
        or "//" in subject_run["path"]
        or not isinstance(subject_run["status"], str)
        or not subject_run["status"]
        or len(subject_run["status"]) > 64
        or (
            subject_run["conclusion"] is not None
            and (not isinstance(subject_run["conclusion"], str) or len(subject_run["conclusion"]) > 64)
        )
    ):
        raise ValueError("state subject run identity is invalid")
    if subject_run is not None:
        _require_sha(subject_run["sha"], "state subject head")
    if controller_run is not None and subject_run is not None and controller_run["id"] == subject_run["id"]:
        raise ValueError("controller and subject run ids must be distinct")
    if not isinstance(state["gates"], dict) or set(state["gates"]) != {
        "deterministic",
        "security",
        "coverage",
    }:
        raise ValueError("state gates are not closed")
    if any(value not in {"pending", "passed", "failed", "blocked"} for value in state["gates"].values()):
        raise ValueError("state gate value is invalid")
    if not isinstance(state["labels"], dict) or set(state["labels"]) != set(FINAL_LABELS):
        raise ValueError("state labels are not closed")
    if any(
        value
        not in {
            "pending",
            "planned",
            "applied",
        }
        for value in state["labels"].values()
    ):
        raise ValueError("state label value is invalid")
    if not isinstance(state["providers"], dict) or set(state["providers"]) != {
        "coderabbit",
        "codex",
    }:
        raise ValueError("state providers are not closed")
    if any(
        value
        not in {
            "pending",
            "blocked",
            "passed",
        }
        for value in state["providers"].values()
    ):
        raise ValueError("state provider value is invalid")
    dependabot = state["dependabot"]
    if (
        not isinstance(dependabot, dict)
        or set(dependabot) != {"eligible", "proof"}
        or not isinstance(dependabot["eligible"], bool)
        or dependabot["proof"] not in {"not-applicable", "disabled"}
    ):
        raise ValueError("state Dependabot proof is invalid")
    requests = state["rerun_requests"]
    if not isinstance(requests, list) or requests:
        raise ValueError("state rerun requests are invalid")
    blockers = state["blockers"]
    if not isinstance(blockers, list) or len(blockers) > 20:
        raise ValueError("state blockers are invalid")
    for item in blockers:
        if (
            not isinstance(item, dict)
            or set(item) != {"code", "detail"}
            or not isinstance(item["code"], str)
            or not item["code"]
            or not isinstance(item["detail"], str)
            or not item["detail"]
        ):
            raise ValueError("state blocker is invalid")
    if not isinstance(state["updated_at"], str) or len(state["updated_at"]) > 64:
        raise ValueError("state timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(state["updated_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("state timestamp is invalid") from exc
    if timestamp.tzinfo is None:
        raise ValueError("state timestamp must include a timezone")
    if state["complete"]:
        if (
            state["phase"] != "complete"
            or state["blockers"]
            or any(value != "passed" for value in state["gates"].values())
            or state["labels"]["ci-final"] != "applied"
            or state["labels"]["ai-review-ready"] != "applied"
            or any(value != "passed" for value in state["providers"].values())
            or state["dependabot"]
            != {
                "eligible": False,
                "proof": "not-applicable",
            }
            or workflow is None
            or controller_run is None
            or subject_run is None
            or controller_run["status"] not in {"in_progress", "completed"}
            or (controller_run["status"] == "completed" and controller_run["conclusion"] != "success")
            or (controller_run["status"] == "in_progress" and controller_run["conclusion"] is not None)
            or subject_run["status"] != "completed"
            or subject_run["conclusion"] != "success"
        ):
            raise ValueError("complete state is internally inconsistent")
    elif state["phase"] == "complete":
        raise ValueError("incomplete state cannot use complete phase")
    if dependabot["eligible"] and (dependabot["proof"] != "disabled" or state["complete"]):
        raise ValueError("Dependabot bypass must remain disabled")


def config_from_environment() -> FinalizerConfig:
    workflow_id_raw = os.environ.get("KOIOS_FINAL_WORKFLOW_ID")
    workflow_path = os.environ.get("KOIOS_FINAL_WORKFLOW_PATH")
    workflow_sha = os.environ.get("KOIOS_PLATFORM_SHA")
    workflow_event = os.environ.get("KOIOS_FINAL_WORKFLOW_EVENT", "workflow_dispatch")
    source_path = os.environ.get("KOIOS_FINAL_SOURCE_PATH")
    promoter_login = os.environ.get("KOIOS_FINAL_PROMOTER_LOGIN")
    promoter_id_raw = os.environ.get("KOIOS_FINAL_PROMOTER_ID")
    promoter_type = os.environ.get("KOIOS_FINAL_PROMOTER_TYPE")
    github_actions = os.environ.get("GITHUB_ACTIONS")
    controller_repository = os.environ.get("GITHUB_REPOSITORY")
    controller_repository_id_raw = os.environ.get("GITHUB_REPOSITORY_ID")
    controller_run_id_raw = os.environ.get("GITHUB_RUN_ID")
    controller_run_attempt_raw = os.environ.get("GITHUB_RUN_ATTEMPT")
    controller_sha = os.environ.get("GITHUB_SHA")
    controller_ref = os.environ.get("GITHUB_REF")
    controller_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    controller_event = os.environ.get("GITHUB_EVENT_NAME")
    subject_run_id_raw = os.environ.get("KOIOS_SUBJECT_RUN_ID")
    subject_run_attempt_raw = os.environ.get("KOIOS_SUBJECT_RUN_ATTEMPT")
    workflow: WorkflowIdentity | None = None
    controller: ControllerIdentity | None = None
    subject_run_id: int | None = None
    subject_run_attempt: int | None = None
    if all(
        (
            workflow_id_raw,
            workflow_path,
            workflow_sha,
            source_path,
            promoter_login,
            promoter_id_raw,
            promoter_type,
            github_actions,
            controller_repository,
            controller_repository_id_raw,
            controller_run_id_raw,
            controller_run_attempt_raw,
            controller_sha,
            controller_ref,
            controller_workflow_ref,
            controller_event,
            subject_run_id_raw,
            subject_run_attempt_raw,
        )
    ):
        workflow_id_raw = cast(str, workflow_id_raw)
        workflow_path = cast(str, workflow_path)
        workflow_sha = cast(str, workflow_sha)
        source_path = cast(str, source_path)
        promoter_login = cast(str, promoter_login)
        promoter_id_raw = cast(str, promoter_id_raw)
        promoter_type = cast(str, promoter_type)
        controller_repository = cast(str, controller_repository)
        controller_repository_id_raw = cast(str, controller_repository_id_raw)
        controller_run_id_raw = cast(str, controller_run_id_raw)
        controller_run_attempt_raw = cast(str, controller_run_attempt_raw)
        controller_sha = cast(str, controller_sha)
        controller_ref = cast(str, controller_ref)
        controller_workflow_ref = cast(str, controller_workflow_ref)
        controller_event = cast(str, controller_event)
        subject_run_id_raw = cast(str, subject_run_id_raw)
        subject_run_attempt_raw = cast(str, subject_run_attempt_raw)
        try:
            workflow_id = int(workflow_id_raw)
            promoter_id = int(promoter_id_raw)
            controller_repository_id = int(controller_repository_id_raw)
            controller_run_id = int(controller_run_id_raw)
            controller_run_attempt = int(controller_run_attempt_raw)
            subject_run_id = int(subject_run_id_raw)
            subject_run_attempt = int(subject_run_attempt_raw)
        except ValueError as exc:
            raise ValueError("workflow, promoter, repository, and run IDs must be integers") from exc
        if github_actions != "true":
            raise ValueError("finalizer must execute inside GitHub Actions")
        if controller_event != workflow_event:
            raise ValueError("configured event does not match the current run")
        workflow_ref_prefix = f"{controller_repository}/"
        workflow_ref_suffix = f"@{controller_ref}"
        if not controller_workflow_ref.startswith(workflow_ref_prefix) or not controller_workflow_ref.endswith(
            workflow_ref_suffix
        ):
            raise ValueError("current workflow ref does not match the trusted controller")
        controller_path = controller_workflow_ref[len(workflow_ref_prefix) : -len(workflow_ref_suffix)]
        if not WORKFLOW_PATH_RE.fullmatch(controller_path):
            raise ValueError("current controller workflow path is not normalized")
        workflow = WorkflowIdentity(
            workflow_id=workflow_id,
            path=workflow_path,
            sha=workflow_sha,
            event=workflow_event,
            source_path=source_path,
            promoter={
                "login": promoter_login,
                "id": promoter_id,
                "type": promoter_type,
            },
        )
        controller = ControllerIdentity(
            path=controller_path,
            event=controller_event,
            repository=controller_repository,
            repository_id=controller_repository_id,
            run_id=controller_run_id,
            run_attempt=controller_run_attempt,
            sha=controller_sha,
            ref=controller_ref,
        )
    provider_verified = os.environ.get("KOIOS_PROVIDER_CONTRACT_VERIFIED") == "1"
    codex_canary_verified = os.environ.get("KOIOS_CODEX_HOSTED_CANARY_VERIFIED") == "1"
    invalidation_verified = os.environ.get("KOIOS_INVALIDATION_CONTROLLER_VERIFIED") == "1"
    latest_run_inventory_verified = os.environ.get("KOIOS_LATEST_RUN_INVENTORY_VERIFIED") == "1"
    external_singleflight_verified = os.environ.get("KOIOS_EXTERNAL_SINGLEFLIGHT_VERIFIED") == "1"
    return FinalizerConfig(
        workflow=workflow,
        controller=controller,
        subject_run_id=subject_run_id,
        subject_run_attempt=subject_run_attempt,
        provider_contract_verified=provider_verified,
        codex_hosted_canary_verified=codex_canary_verified,
        invalidation_controller_verified=invalidation_verified,
        latest_run_inventory_verified=latest_run_inventory_verified,
        external_singleflight_verified=external_singleflight_verified,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="koios-ci")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("KOIOS_CI_STATE_DIR", ".koios-ci/finalizer")),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_target(subparser: argparse.ArgumentParser, *, require_head: bool) -> None:
        subparser.add_argument("--repo", required=True)
        subparser.add_argument("--pr", required=True, type=int)
        if require_head:
            subparser.add_argument("--head", required=True)

    def add_execution(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--dry-run", action="store_true")
        subparser.add_argument("--rerun-failed", action="store_true")
        subparser.add_argument("--timeout-seconds", type=int, default=0)
        subparser.add_argument("--poll-seconds", type=int, default=1)

    finalize = subparsers.add_parser("finalize")
    add_target(finalize, require_head=False)
    add_execution(finalize)

    resume = subparsers.add_parser("resume")
    add_target(resume, require_head=True)
    add_execution(resume)

    status = subparsers.add_parser("status")
    add_target(status, require_head=True)
    status.add_argument("--json", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    api: FinalizerAPI | None = None,
    stdout: TextIO | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output = stdout or sys.stdout
    try:
        adapter = api or GitHubRestAPI.from_environment()
        finalizer = Finalizer(
            api=adapter,
            state_dir=args.state_dir,
            config=config_from_environment(),
        )
        if args.command == "finalize":
            result = finalizer.finalize(
                args.repo,
                args.pr,
                dry_run=args.dry_run,
                rerun_failed=args.rerun_failed,
                timeout_seconds=args.timeout_seconds,
                poll_seconds=args.poll_seconds,
            )
        elif args.command == "resume":
            result = finalizer.resume(
                args.repo,
                args.pr,
                args.head,
                dry_run=args.dry_run,
                rerun_failed=args.rerun_failed,
                timeout_seconds=args.timeout_seconds,
                poll_seconds=args.poll_seconds,
            )
        else:
            result = finalizer.status(args.repo, args.pr, args.head)
        if args.command != "status" or args.json:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
        else:
            output.write(
                f"{result['key']['repository']}#{result['key']['pull_request']} "
                f"{result['key']['head_sha']} {result['phase']}\n"
            )
        return 0 if result["complete"] else 2
    except (
        BoundaryViolation,
        FileNotFoundError,
        GitHubAPIError,
        ProviderUnavailable,
        RuntimeError,
        ValueError,
    ) as exc:
        json.dump(
            {
                "complete": False,
                "error": type(exc).__name__,
                "message": str(exc),
            },
            output,
            indent=2,
            sort_keys=True,
        )
        output.write("\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
