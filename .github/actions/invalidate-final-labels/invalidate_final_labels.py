"""Idempotently remove final-review labels after a PR head update."""

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

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
FINAL_LABELS = frozenset({"ai-review-ready", "ci-final"})
API_URL = "https://api.github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
MAX_INVALIDATION_ATTEMPTS = 3
INVALIDATION_EVENTS = frozenset({"synchronize", "reopened", "converted_to_draft"})


class ApiError(RuntimeError):
    """An unambiguous GitHub API HTTP failure."""

    def __init__(self, method: str, path: str, status: int) -> None:
        self.status = status
        super().__init__(f"GitHub API {method} {path} failed with HTTP {status}")


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


def trusted_action_source(
    action_repository: str,
    action_ref: str,
    trusted_source_sha: str,
    workflow_source_sha: str,
) -> bool:
    """Accept an immutable remote action or the exact protected-base local canary."""
    remote = action_repository == ACTION_REPOSITORY and FULL_SHA.fullmatch(action_ref) is not None
    local = (
        action_repository in {"", ACTION_REPOSITORY}
        and action_ref == ""
        and FULL_SHA.fullmatch(trusted_source_sha) is not None
        and trusted_source_sha == workflow_source_sha
    )
    return remote or local


def labels_to_remove(
    pull: Mapping[str, Any],
    event_head_sha: str,
    lifecycle_event: str = "synchronize",
) -> list[str]:
    if not FULL_SHA.fullmatch(event_head_sha):
        raise ValueError("event head is not a full lowercase commit SHA")
    if lifecycle_event not in INVALIDATION_EVENTS:
        raise ValueError("unsupported pull request lifecycle event")
    head = pull.get("head")
    if pull.get("state") != "open" or not isinstance(head, Mapping) or head.get("sha") != event_head_sha:
        return []
    labels = pull.get("labels")
    if not isinstance(labels, list):
        raise ValueError("pull request labels are malformed")
    observed: set[str] = set()
    for label in labels:
        name = label.get("name") if isinstance(label, Mapping) else None
        if isinstance(name, str):
            observed.add(name)
    return sorted(FINAL_LABELS & observed)


def current_final_labels(
    pull: Mapping[str, Any],
    event_head_sha: str,
    lifecycle_event: str = "synchronize",
) -> set[str]:
    """Require an exact open-head snapshot and return its final labels."""
    if not FULL_SHA.fullmatch(event_head_sha):
        raise ValueError("event head is not a full lowercase commit SHA")
    if lifecycle_event not in INVALIDATION_EVENTS:
        raise ValueError("unsupported pull request lifecycle event")
    head = pull.get("head")
    if pull.get("state") != "open" or not isinstance(head, Mapping) or head.get("sha") != event_head_sha:
        raise ValueError("pull request is no longer the exact synchronized head")
    if lifecycle_event == "converted_to_draft" and pull.get("draft") is not True:
        raise ValueError("converted_to_draft readback does not show a draft pull request")
    labels = pull.get("labels")
    if not isinstance(labels, list):
        raise ValueError("pull request labels are malformed")
    observed: set[str] = set()
    for label in labels:
        name = label.get("name") if isinstance(label, Mapping) else None
        if isinstance(name, str):
            observed.add(name)
    if len(observed) != len(labels):
        raise ValueError("pull request labels are malformed")
    return set(FINAL_LABELS & observed)


def api_request(
    method: str,
    path: str,
    *,
    token: str,
    expect_empty: bool = False,
) -> Any:
    if (
        method not in {"DELETE", "GET"}
        or not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or "\\" in path
        or any(character in path for character in "\r\n")
    ):
        raise ValueError("GitHub API request is outside the closed boundary")
    expected_url = f"{API_URL}{path}"
    request = urllib.request.Request(
        expected_url,
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
            if response.geturl() != expected_url:
                raise RuntimeError("GitHub API redirect refused")
            status = getattr(response, "status", None)
            if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 300:
                raise RuntimeError("GitHub API returned a malformed HTTP status")
            payload = response.read()
            if expect_empty and not payload:
                return None
            return json.loads(payload.decode("utf-8")) if payload else None
    except urllib.error.HTTPError as error:
        raise ApiError(method, path, error.code) from error
    except (TimeoutError, urllib.error.URLError) as error:
        raise RuntimeError(f"GitHub API {method} {path} request failed") from error


def invalidate_final_labels(
    repository: str,
    number: int,
    head_sha: str,
    initial_pull: Mapping[str, Any],
    *,
    token: str,
    lifecycle_event: str = "synchronize",
) -> bool:
    """Remove both labels best-effort and succeed only after exact-head readback."""
    initial = current_final_labels(initial_pull, head_sha, lifecycle_event)
    pending = set(initial)
    accepted_delete = False
    failures: list[str] = []
    for attempt in range(1, MAX_INVALIDATION_ATTEMPTS + 1):
        for label in sorted(pending):
            encoded = urllib.parse.quote(label, safe="")
            try:
                api_request(
                    "DELETE",
                    f"/repos/{repository}/issues/{number}/labels/{encoded}",
                    token=token,
                    expect_empty=True,
                )
                accepted_delete = True
            except ApiError as error:
                if error.status != 404:
                    failures.append(f"attempt {attempt} delete {label}: HTTP {error.status}")
            except RuntimeError:
                failures.append(f"attempt {attempt} delete {label}: transport failure")

        try:
            readback = api_request(
                "GET",
                f"/repos/{repository}/pulls/{number}",
                token=token,
            )
        except RuntimeError:
            failures.append(f"attempt {attempt} exact-head readback: API failure")
        else:
            if not isinstance(readback, Mapping):
                raise RuntimeError("GitHub returned malformed pull request readback")
            remaining = current_final_labels(readback, head_sha, lifecycle_event)
            if not remaining:
                return accepted_delete or bool(initial)
            pending = remaining

        if attempt < MAX_INVALIDATION_ATTEMPTS:
            time.sleep(attempt)

    remaining_labels = ", ".join(sorted(pending)) or "readback-unconfirmed"
    failure_summary = "; ".join(failures[-6:]) or "no API error detail"
    raise RuntimeError(
        "final-label invalidation could not confirm both labels absent; "
        f"remaining={remaining_labels}; failures={failure_summary}"
    )


def main() -> None:
    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    api_url = os.environ.get("GITHUB_API_URL", "")
    action_repository = os.environ.get("ACTION_REPOSITORY", "")
    action_ref = os.environ.get("ACTION_REF", "")
    trusted_source_sha = os.environ.get("INPUT_TRUSTED_SOURCE_SHA", "")
    workflow_source_sha = os.environ.get("WORKFLOW_SOURCE_SHA", "")
    if (
        not token
        or not repository
        or "/" not in repository
        or api_url != API_URL
        or not trusted_action_source(
            action_repository,
            action_ref,
            trusted_source_sha,
            workflow_source_sha,
        )
    ):
        raise ValueError("trusted GitHub or immutable action identity is unavailable")
    raw_number = os.environ["INPUT_PULL_REQUEST_NUMBER"]
    if not raw_number.isdecimal() or int(raw_number) < 1:
        raise ValueError("invalid pull request number")
    number = int(raw_number)
    head_sha = os.environ["INPUT_EVENT_HEAD_SHA"]
    lifecycle_event = os.environ["INPUT_LIFECYCLE_EVENT"]
    pull = api_request("GET", f"/repos/{repository}/pulls/{number}", token=token)
    if not isinstance(pull, Mapping):
        raise RuntimeError("GitHub returned malformed pull request metadata")
    changed = invalidate_final_labels(
        repository,
        number,
        head_sha,
        pull,
        token=token,
        lifecycle_event=lifecycle_event,
    )
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"changed={str(changed).lower()}\n")


if __name__ == "__main__":
    main()
