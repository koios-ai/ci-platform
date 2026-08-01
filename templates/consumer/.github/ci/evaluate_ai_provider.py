"""Read-only evaluator for provider-native final-review evidence.

This file is intentionally consumer-local.  The organization-required
integrity workflow verifies its exact digest before a protected branch may
accept a change.  It performs metadata reads only and never creates checks,
statuses, reviews, comments, labels, or commits.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any, TypedDict

API_URL = "https://api.github.com"
GRAPHQL_URL = f"{API_URL}/graphql"
DEFAULT_BRANCH = "main"


class ProviderIdentity(TypedDict):
    review_login: str
    delivery_login: str
    delivery_app_id: int
    delivery_app_slug: str
    check_name: str | None
    provider_mode: str


PROVIDERS: dict[str, ProviderIdentity] = {
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
FAILURE_MARKERS = (
    "review skipped",
    "usage limit",
    "rate limit",
    "quota exceeded",
    "out of credits",
    "provider error",
    "temporarily unavailable",
    "failed to review",
    "unable to review",
    "not reviewed",
)


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
) -> Any:
    if not path.startswith("/") or "://" in path:
        raise ValueError("GitHub API path is not repository-relative")
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "koios-ai-review-evaluator",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _opener().open(request, timeout=30) as response:
            final_url = response.geturl()
            if final_url != f"{API_URL}{path}":
                raise RuntimeError("GitHub API response changed origin or path")
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GitHub API {method} {path} failed with HTTP {error.code}") from error
    except (TimeoutError, urllib.error.URLError) as error:
        raise RuntimeError(f"GitHub API {method} request failed") from error


def paginate(repository: str, endpoint: str, *, token: str) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    separator = "&" if "?" in endpoint else "?"
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (f"/repos/{repository}/{endpoint}{separator}per_page=100&page={page}"),
            token=token,
        )
        if not isinstance(payload, list) or not all(isinstance(item, Mapping) for item in payload):
            raise RuntimeError("GitHub returned malformed pagination")
        values.extend(payload)
        if len(payload) < 100:
            return values
    raise RuntimeError("GitHub pagination exceeded the bounded page limit")


def paginate_check_runs(repository: str, head_sha: str, *, token: str) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        payload = api_request(
            "GET",
            (f"/repos/{repository}/commits/{head_sha}/check-runs?filter=all&per_page=100&page={page}"),
            token=token,
        )
        rows = payload.get("check_runs") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list) or not all(isinstance(item, Mapping) for item in rows):
            raise RuntimeError("GitHub returned malformed check-run pagination")
        values.extend(rows)
        if len(rows) < 100:
            return values
    raise RuntimeError("GitHub check-run pagination exceeded the bounded page limit")


def graphql(
    query: str,
    variables: Mapping[str, Any],
    *,
    token: str,
) -> Mapping[str, Any]:
    if not query.startswith(("query ReviewThreads(", "query ReviewThreadComments(")):
        raise ValueError("only the fixed review-thread queries are allowed")
    request = urllib.request.Request(
        GRAPHQL_URL,
        data=json.dumps({"query": query, "variables": variables}).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "koios-ai-review-evaluator",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _opener().open(request, timeout=30) as response:
            if response.geturl() != GRAPHQL_URL:
                raise RuntimeError("GitHub GraphQL response changed origin or path")
            loaded = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GitHub GraphQL failed with HTTP {error.code}") from error
    except (TimeoutError, urllib.error.URLError) as error:
        raise RuntimeError("GitHub GraphQL request failed") from error
    if not isinstance(loaded, Mapping) or loaded.get("errors"):
        raise RuntimeError("GitHub GraphQL returned errors or malformed data")
    data = loaded.get("data")
    if not isinstance(data, Mapping):
        raise RuntimeError("GitHub GraphQL returned errors or malformed data")
    return data


REVIEW_THREADS_QUERY = """query ReviewThreads(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $after: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          comments(first: 100) {
            pageInfo { hasNextPage endCursor }
            nodes { author { login } }
          }
        }
      }
    }
  }
}"""

REVIEW_THREAD_COMMENTS_QUERY = """query ReviewThreadComments(
  $id: ID!,
  $after: String
) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      comments(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes { author { login } }
      }
    }
  }
}"""


def review_threads(
    repository: str,
    number: int,
    *,
    token: str,
) -> list[Mapping[str, Any]]:
    owner, name = repository.split("/", 1)
    nodes: list[Mapping[str, Any]] = []
    cursor: str | None = None
    for _page in range(100):
        data = graphql(
            REVIEW_THREADS_QUERY,
            {
                "owner": owner,
                "name": name,
                "number": number,
                "after": cursor,
            },
            token=token,
        )
        repo = data.get("repository")
        pull = repo.get("pullRequest") if isinstance(repo, Mapping) else None
        threads = pull.get("reviewThreads") if isinstance(pull, Mapping) else None
        if not isinstance(threads, Mapping):
            raise RuntimeError("review-thread response is incomplete")
        page_nodes = threads.get("nodes")
        page_info = threads.get("pageInfo")
        if (
            not isinstance(page_nodes, list)
            or not all(isinstance(item, Mapping) for item in page_nodes)
            or not isinstance(page_info, Mapping)
        ):
            raise RuntimeError("review-thread pagination is malformed")
        for thread in page_nodes:
            thread_id = thread.get("id")
            comments = thread.get("comments")
            comment_page = comments.get("pageInfo") if isinstance(comments, Mapping) else None
            comment_nodes = comments.get("nodes") if isinstance(comments, Mapping) else None
            if (
                not isinstance(thread_id, str)
                or not thread_id
                or not isinstance(comment_page, Mapping)
                or not isinstance(comment_nodes, list)
                or not all(isinstance(item, Mapping) for item in comment_nodes)
            ):
                raise RuntimeError("review-thread comments are malformed")
            flattened_comments = list(comment_nodes)
            comment_cursor = comment_page.get("endCursor")
            for _comment_page in range(100):
                if comment_page.get("hasNextPage") is False:
                    break
                if not isinstance(comment_cursor, str) or not comment_cursor:
                    raise RuntimeError("review-thread comment cursor is malformed")
                nested_data = graphql(
                    REVIEW_THREAD_COMMENTS_QUERY,
                    {"id": thread_id, "after": comment_cursor},
                    token=token,
                )
                node = nested_data.get("node")
                nested = node.get("comments") if isinstance(node, Mapping) else None
                if not isinstance(nested, Mapping):
                    raise RuntimeError("review-thread nested comments are incomplete")
                nested_nodes = nested.get("nodes")
                comment_page = nested.get("pageInfo")
                if (
                    not isinstance(nested_nodes, list)
                    or not all(isinstance(item, Mapping) for item in nested_nodes)
                    or not isinstance(comment_page, Mapping)
                ):
                    raise RuntimeError("review-thread nested pagination is malformed")
                flattened_comments.extend(nested_nodes)
                comment_cursor = comment_page.get("endCursor")
            else:
                raise RuntimeError("review-thread comment pagination exceeded the bounded page limit")
            if comment_page.get("hasNextPage") is not False:
                raise RuntimeError("review-thread nested pagination did not close")
            nodes.append(
                {
                    "isResolved": thread.get("isResolved"),
                    "comments": {
                        "nodes": flattened_comments,
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    },
                }
            )
        if page_info.get("hasNextPage") is False:
            return nodes
        cursor = page_info.get("endCursor")
        if not isinstance(cursor, str) or not cursor:
            raise RuntimeError("review-thread cursor is malformed")
    raise RuntimeError("review-thread pagination exceeded the bounded page limit")


def _timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _login(value: Mapping[str, Any]) -> str:
    user = value.get("user")
    return str(user.get("login", "")) if isinstance(user, Mapping) else ""


def failure_markers(*texts: Any) -> list[str]:
    combined = "\n".join(str(text or "").lower() for text in texts)
    return sorted({marker for marker in FAILURE_MARKERS if marker in combined})


def _latest_unique(
    rows: Sequence[Mapping[str, Any]],
    timestamp_field: str,
) -> tuple[Mapping[str, Any] | None, bool]:
    identities: set[int] = set()
    ordered: list[tuple[dt.datetime, int, Mapping[str, Any]]] = []
    for row in rows:
        row_id = row.get("id")
        timestamp = _timestamp(row.get(timestamp_field))
        if (
            isinstance(row_id, bool)
            or not isinstance(row_id, int)
            or row_id < 1
            or row_id in identities
            or timestamp is None
        ):
            return None, True
        identities.add(row_id)
        ordered.append((timestamp, row_id, row))
    ordered.sort(key=lambda item: (item[0], item[1]))
    return (ordered[-1][2] if ordered else None), False


def _text_digest(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _provider_unresolved_threads(threads: list[Mapping[str, Any]], login: str) -> int:
    unresolved = 0
    for thread in threads:
        comments = thread.get("comments")
        nodes = comments.get("nodes", []) if isinstance(comments, Mapping) else []
        authors = {
            str(author.get("login", ""))
            for comment in nodes
            if isinstance(comment, Mapping)
            for author in [comment.get("author")]
            if isinstance(author, Mapping)
        }
        if thread.get("isResolved") is not True and login in authors:
            unresolved += 1
    return unresolved


def _all_unresolved_threads(threads: list[Mapping[str, Any]]) -> int:
    return sum(thread.get("isResolved") is not True for thread in threads)


def _app(value: Mapping[str, Any]) -> Mapping[str, Any]:
    app = value.get("performed_via_github_app")
    return app if isinstance(app, Mapping) else {}


def evaluate_provider(
    provider: str,
    *,
    head_sha: str,
    reviews: list[Mapping[str, Any]],
    issue_comments: list[Mapping[str, Any]],
    review_comments: list[Mapping[str, Any]],
    checks: list[Mapping[str, Any]],
    threads: list[Mapping[str, Any]],
    codex_hosted_canary_verified: bool = False,
) -> tuple[bool, dict[str, Any], str]:
    identity = PROVIDERS[provider]
    login = str(identity["review_login"])
    bot_reviews = [review for review in reviews if _login(review) == login]
    deliveries = [
        comment for comment in [*issue_comments, *review_comments] if _login(comment) == identity["delivery_login"]
    ]
    normalized_deliveries = [
        {**comment, "ordering_at": comment.get("updated_at") or comment.get("created_at")} for comment in deliveries
    ]
    check_name = identity["check_name"]
    native = [check for check in checks if check_name is not None and check.get("name") == check_name]
    normalized_checks = [
        {**check, "ordering_at": check.get("completed_at") or check.get("started_at")} for check in native
    ]
    latest, review_invalid = _latest_unique(bot_reviews, "submitted_at")
    delivery, delivery_invalid = _latest_unique(normalized_deliveries, "ordering_at")
    native_latest, check_invalid = _latest_unique(normalized_checks, "ordering_at")
    latest = latest or {}
    delivery = delivery or {}
    native_latest = native_latest or {}
    malformed = review_invalid or delivery_invalid or check_invalid
    output = native_latest.get("output")
    if native_latest and (
        not isinstance(output, Mapping)
        or not {"title", "summary", "text"} <= set(output)
        or any(
            output.get(field) is not None and not isinstance(output.get(field), str)
            for field in ("title", "summary", "text")
        )
    ):
        malformed = True
    markers = failure_markers(
        latest.get("body"),
        delivery.get("body"),
        *(output.get(field) if isinstance(output, Mapping) else "" for field in ("title", "summary", "text")),
    )
    unresolved = _provider_unresolved_threads(threads, login)
    review_time = _timestamp(latest.get("submitted_at"))
    delivery_time = _timestamp(delivery.get("ordering_at"))
    review_body = latest.get("body")
    delivery_body = delivery.get("body")
    app = _app(delivery)
    review_valid = (
        bool(latest)
        and latest.get("commit_id") == head_sha
        and latest.get("state") in {"APPROVED", "COMMENTED"}
        and isinstance(review_body, str)
        and len(review_body) <= 200_000
    )
    delivery_valid = (
        bool(delivery)
        and app.get("id") == identity["delivery_app_id"]
        and app.get("slug") == identity["delivery_app_slug"]
        and isinstance(delivery_body, str)
        and len(delivery_body) <= 200_000
        and review_time is not None
        and delivery_time is not None
        and delivery_time >= review_time
    )
    check_app = native_latest.get("app") if isinstance(native_latest, Mapping) else None
    check_valid = check_name is None or (
        bool(native_latest)
        and native_latest.get("head_sha") == head_sha
        and native_latest.get("status") == "completed"
        and native_latest.get("conclusion") == "success"
        and isinstance(check_app, Mapping)
        and check_app.get("id") == identity["delivery_app_id"]
        and check_app.get("slug") == identity["delivery_app_slug"]
    )
    canary_valid = provider != "codex" or codex_hosted_canary_verified
    explicit_result_valid = provider != "codex" or (isinstance(review_body, str) and review_body.strip() == "PASS")
    passed = bool(
        not malformed
        and review_valid
        and delivery_valid
        and check_valid
        and canary_valid
        and explicit_result_valid
        and unresolved == 0
        and not markers
    )
    reason = "pass" if passed else "provider-evidence-malformed" if malformed else "provider-evidence-incomplete"
    details = {
        "review_login": identity["review_login"],
        "delivery_login": identity["delivery_login"],
        "delivery_app_id": identity["delivery_app_id"],
        "delivery_app_slug": identity["delivery_app_slug"],
        "check_name": identity["check_name"],
        "provider_mode": identity["provider_mode"],
        "hosted_canary_verified": provider != "codex" or codex_hosted_canary_verified,
        "review_id": int(latest.get("id", 0)),
        "review_commit_id": str(latest.get("commit_id", "")),
        "review_state": str(latest.get("state", "")),
        "delivery_comment_id": int(delivery.get("id", 0)),
        "native_check_id": int(native_latest.get("id", 0)),
        "native_check_conclusion": str(native_latest.get("conclusion", "")),
        "review_body_sha256": _text_digest(latest.get("body")),
        "delivery_body_sha256": _text_digest(delivery.get("body")),
        "unresolved_threads": unresolved,
        "failure_markers": markers,
    }
    return passed, details, reason


def collect_snapshot(
    repository: str,
    number: int,
    *,
    token: str,
) -> dict[str, list[Mapping[str, Any]]]:
    return {
        "reviews": paginate(repository, f"pulls/{number}/reviews", token=token),
        "issue_comments": paginate(repository, f"issues/{number}/comments", token=token),
        "review_comments": paginate(repository, f"pulls/{number}/comments", token=token),
        "checks": paginate_check_runs(repository, os.environ["EXPECTED_HEAD_SHA"], token=token),
        "threads": review_threads(repository, number, token=token),
    }


def evidence_document(
    provider: str,
    *,
    repository: str,
    repository_id: int,
    number: int,
    head_sha: str,
    base_sha: str,
    source_sha: str,
    evaluator_path: pathlib.Path,
    snapshot: Mapping[str, list[Mapping[str, Any]]],
    codex_hosted_canary_verified: bool = False,
) -> dict[str, Any]:
    if provider in PROVIDERS:
        passed, details, reason = evaluate_provider(
            provider,
            head_sha=head_sha,
            reviews=list(snapshot["reviews"]),
            issue_comments=list(snapshot["issue_comments"]),
            review_comments=list(snapshot["review_comments"]),
            checks=list(snapshot["checks"]),
            threads=list(snapshot["threads"]),
            codex_hosted_canary_verified=codex_hosted_canary_verified,
        )
    else:
        rabbit_passed, rabbit_details, _ = evaluate_provider(
            "coderabbit",
            head_sha=head_sha,
            reviews=list(snapshot["reviews"]),
            issue_comments=list(snapshot["issue_comments"]),
            review_comments=list(snapshot["review_comments"]),
            checks=list(snapshot["checks"]),
            threads=list(snapshot["threads"]),
        )
        codex_passed, codex_details, _ = evaluate_provider(
            "codex",
            head_sha=head_sha,
            reviews=list(snapshot["reviews"]),
            issue_comments=list(snapshot["issue_comments"]),
            review_comments=list(snapshot["review_comments"]),
            checks=list(snapshot["checks"]),
            threads=list(snapshot["threads"]),
            codex_hosted_canary_verified=codex_hosted_canary_verified,
        )
        unresolved = _all_unresolved_threads(list(snapshot["threads"]))
        combined_markers = sorted(
            {
                *rabbit_details["failure_markers"],
                *codex_details["failure_markers"],
            }
        )
        passed = rabbit_passed and codex_passed and unresolved == 0 and not combined_markers
        reason = "pass" if passed else "findings-remain-or-provider-incomplete"
        details = {
            "coderabbit_current_head": rabbit_passed,
            "coderabbit_evidence_digest": hashlib.sha256(
                json.dumps(rabbit_details, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "codex_current_head": codex_passed,
            "codex_evidence_digest": hashlib.sha256(
                json.dumps(codex_details, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "unresolved_threads": unresolved,
            "failure_markers": combined_markers,
        }
    return {
        "schema_version": 1,
        "provider": provider,
        "repository": repository,
        "repository_id": repository_id,
        "pull_request_number": number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "checked_at": (dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")),
        "evaluator": {
            "path": ".github/ci/evaluate_ai_provider.py",
            "sha256": hashlib.sha256(evaluator_path.read_bytes()).hexdigest(),
            "source_sha": source_sha,
        },
        "passed": passed,
        "reason": reason,
        "provider_evidence": details,
    }


def validate_pull(
    repository: str,
    number: int,
    *,
    token: str,
    head_sha: str,
    base_sha: str,
) -> None:
    pull = api_request("GET", f"/repos/{repository}/pulls/{number}", token=token)
    if not isinstance(pull, Mapping):
        raise RuntimeError("GitHub returned malformed pull metadata")
    head = pull.get("head")
    base = pull.get("base")
    head_repo = head.get("repo") if isinstance(head, Mapping) else None
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if isinstance(base, Mapping) and base.get("ref") != DEFAULT_BRANCH:
        raise RuntimeError("pull request does not target the protected default branch")
    if (
        pull.get("state") != "open"
        or pull.get("draft") is not False
        or not isinstance(head, Mapping)
        or head.get("sha") != head_sha
        or not isinstance(head_repo, Mapping)
        or head_repo.get("full_name") != repository
        or not isinstance(base, Mapping)
        or base.get("sha") != base_sha
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != repository
        or not isinstance(head_repo.get("id"), int)
        or head_repo.get("id") != base_repo.get("id")
    ):
        raise RuntimeError("pull request changed during provider evaluation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--provider",
        choices=(*PROVIDERS, "findings"),
        required=True,
    )
    parser.add_argument("--timeout-seconds", type=int, default=0)
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0 <= args.timeout_seconds <= 900:
        raise ValueError("provider polling timeout is outside the bounded range")
    if not 10 <= args.poll_seconds <= 60:
        raise ValueError("provider poll interval is outside the bounded range")
    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    raw_number = os.environ.get("PULL_REQUEST_NUMBER", "")
    raw_repository_id = os.environ.get("GITHUB_REPOSITORY_ID", "")
    head_sha = os.environ.get("EXPECTED_HEAD_SHA", "")
    base_sha = os.environ.get("EXPECTED_BASE_SHA", "")
    source_sha = os.environ.get("EVALUATOR_SOURCE_SHA", "")
    codex_hosted_canary_verified = os.environ.get("KOIOS_CODEX_HOSTED_CANARY_VERIFIED") == "1"
    if (
        not token
        or "/" not in repository
        or not raw_number.isdecimal()
        or not raw_repository_id.isdecimal()
        or len(head_sha) != 40
        or len(base_sha) != 40
        or source_sha != base_sha
    ):
        raise ValueError("provider evaluator runtime is incomplete")
    number = int(raw_number)
    evaluator_path = pathlib.Path(__file__).resolve()
    deadline = time.monotonic() + args.timeout_seconds
    document: dict[str, Any] | None = None
    while True:
        validate_pull(
            repository,
            number,
            token=token,
            head_sha=head_sha,
            base_sha=base_sha,
        )
        snapshot = collect_snapshot(repository, number, token=token)
        document = evidence_document(
            args.provider,
            repository=repository,
            repository_id=int(raw_repository_id),
            number=number,
            head_sha=head_sha,
            base_sha=base_sha,
            source_sha=source_sha,
            evaluator_path=evaluator_path,
            snapshot=snapshot,
            codex_hosted_canary_verified=codex_hosted_canary_verified,
        )
        if document["passed"] or time.monotonic() >= deadline:
            break
        time.sleep(args.poll_seconds)
    validate_pull(
        repository,
        number,
        token=token,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"evidence_digest={digest}\n")
        output.write(f"passed={str(bool(document['passed'])).lower()}\n")


if __name__ == "__main__":
    main()
