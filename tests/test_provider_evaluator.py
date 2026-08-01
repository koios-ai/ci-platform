from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "templates" / "consumer" / ".github" / "ci" / "evaluate_ai_provider.py"
HEAD = "a" * 40
OLD = "b" * 40


def load_module(name: str = "provider_evaluator") -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def review(
    login: str,
    *,
    review_id: int,
    commit_id: str = HEAD,
    body: str | None = None,
    state: str = "COMMENTED",
    submitted_at: str = "2026-07-26T20:00:00Z",
) -> dict[str, Any]:
    return {
        "id": review_id,
        "user": {"login": login},
        "commit_id": commit_id,
        "body": "Provider-native review completed" if body is None else body,
        "state": state,
        "submitted_at": submitted_at,
    }


def delivery(
    login: str,
    *,
    comment_id: int,
    app_id: int,
    app_slug: str,
    body: str | None = None,
    head_sha: str = HEAD,
    updated_at: str = "2026-07-26T20:01:00Z",
) -> dict[str, Any]:
    return {
        "id": comment_id,
        "user": {"login": login},
        "performed_via_github_app": {"id": app_id, "slug": app_slug},
        "body": "Provider-native App delivery completed" if body is None else body,
        "updated_at": updated_at,
    }


def coderabbit_check(
    *,
    check_id: int = 3,
    head_sha: str = HEAD,
    conclusion: str = "success",
    app_id: int = 347564,
    app_slug: str = "coderabbitai",
    completed_at: str = "2026-07-26T20:02:00Z",
) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": "CodeRabbit",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"id": app_id, "slug": app_slug},
        "started_at": "2026-07-26T20:00:00Z",
        "completed_at": completed_at,
        "output": {"title": "CodeRabbit", "summary": "Review completed", "text": ""},
    }


def test_coderabbit_requires_latest_current_head_review_and_exact_app() -> None:
    module = load_module()
    reviews = [
        review(
            "coderabbitai[bot]",
            review_id=1,
            commit_id=HEAD,
            submitted_at="2026-07-26T20:00:00Z",
        )
    ]
    comments = [
        delivery(
            "coderabbitai[bot]",
            comment_id=2,
            app_id=347564,
            app_slug="coderabbitai",
        )
    ]
    passed, details, reason = module.evaluate_provider(
        "coderabbit",
        head_sha=HEAD,
        reviews=reviews,
        issue_comments=comments,
        review_comments=[],
        checks=[coderabbit_check()],
        threads=[],
    )
    assert passed is True
    assert reason == "pass"
    assert details["delivery_app_id"] == 347564
    assert details["provider_mode"] == "native-review-app-check"
    assert details["native_check_id"] == 3

    newer_stale = review(
        "coderabbitai[bot]",
        review_id=4,
        commit_id=OLD,
        submitted_at="2026-07-26T20:03:00Z",
    )
    assert (
        module.evaluate_provider(
            "coderabbit",
            head_sha=HEAD,
            reviews=[*reviews, newer_stale],
            issue_comments=comments,
            review_comments=[],
            checks=[coderabbit_check()],
            threads=[],
        )[0]
        is False
    )
    wrong_app = [{**comments[0], "performed_via_github_app": {"id": 1, "slug": "coderabbitai"}}]
    assert (
        module.evaluate_provider(
            "coderabbit",
            head_sha=HEAD,
            reviews=reviews,
            issue_comments=wrong_app,
            review_comments=[],
            checks=[coderabbit_check()],
            threads=[],
        )[0]
        is False
    )


@pytest.mark.parametrize(
    "message",
    [
        "Review skipped due to plan",
        "Usage limit reached",
        "Provider error",
        "Out of credits",
    ],
)
def test_provider_failure_and_usage_messages_are_never_success(message: str) -> None:
    module = load_module(f"provider_failure_{message.split()[0]}")
    passed, details, _ = module.evaluate_provider(
        "coderabbit",
        head_sha=HEAD,
        reviews=[
            review(
                "coderabbitai[bot]",
                review_id=1,
                body=f"CodeRabbit review details: {message}",
            )
        ],
        issue_comments=[
            delivery(
                "coderabbitai[bot]",
                comment_id=2,
                app_id=347564,
                app_slug="coderabbitai",
            )
        ],
        review_comments=[],
        checks=[coderabbit_check()],
        threads=[],
    )
    assert passed is False
    assert details["failure_markers"]


@pytest.mark.parametrize("mutation", ["duplicate", "malformed", "wrong-check-app"])
def test_coderabbit_native_evidence_fails_closed_on_ambiguous_shapes(mutation: str) -> None:
    module = load_module(f"provider_native_{mutation}")
    reviews = [review("coderabbitai[bot]", review_id=1)]
    checks = [coderabbit_check()]
    if mutation == "duplicate":
        reviews.append(review("coderabbitai[bot]", review_id=1))
    elif mutation == "malformed":
        reviews[0]["submitted_at"] = "not-a-timestamp"
    else:
        checks = [coderabbit_check(app_id=1)]
    passed, _, _ = module.evaluate_provider(
        "coderabbit",
        head_sha=HEAD,
        reviews=reviews,
        issue_comments=[
            delivery(
                "coderabbitai[bot]",
                comment_id=2,
                app_id=347564,
                app_slug="coderabbitai",
            )
        ],
        review_comments=[],
        checks=checks,
        threads=[],
    )
    assert passed is False


def test_codex_native_evidence_cannot_mint_a_pass_without_hosted_canary() -> None:
    module = load_module("provider_codex")
    passed, details, _ = module.evaluate_provider(
        "codex",
        head_sha=HEAD,
        reviews=[
            review(
                "chatgpt-codex-connector[bot]",
                review_id=10,
                body="Codex code review findings",
            )
        ],
        issue_comments=[],
        review_comments=[
            delivery(
                "chatgpt-codex-connector[bot]",
                comment_id=11,
                app_id=1144995,
                app_slug="chatgpt-codex-connector",
            )
        ],
        checks=[],
        threads=[],
    )
    assert passed is False
    assert details["hosted_canary_verified"] is False
    assert details["provider_mode"] == "native-review-app-hosted-canary-required"


def test_codex_hosted_canary_mode_requires_exact_current_head_and_app_delivery() -> None:
    module = load_module("provider_codex_explicit_pass")
    passed, details, reason = module.evaluate_provider(
        "codex",
        head_sha=HEAD,
        reviews=[
            review(
                "chatgpt-codex-connector[bot]",
                review_id=10,
                body="PASS",
            )
        ],
        issue_comments=[],
        review_comments=[
            delivery(
                "chatgpt-codex-connector[bot]",
                comment_id=11,
                app_id=1144995,
                app_slug="chatgpt-codex-connector",
            )
        ],
        checks=[],
        threads=[],
        codex_hosted_canary_verified=True,
    )
    assert passed is True
    assert reason == "pass"
    assert details["hosted_canary_verified"] is True

    for body in (
        "PASS",
        "Provider-native review completed",
        "Review skipped due to rate limit",
        "Provider error",
    ):
        changed, _, _ = module.evaluate_provider(
            "codex",
            head_sha=HEAD,
            reviews=[
                review(
                    "chatgpt-codex-connector[bot]",
                    review_id=10,
                    body=body,
                )
            ],
            issue_comments=[],
            review_comments=[
                delivery(
                    "chatgpt-codex-connector[bot]",
                    comment_id=11,
                    app_id=1144995,
                    app_slug="chatgpt-codex-connector",
                )
            ],
            checks=[],
            threads=[],
            codex_hosted_canary_verified=True,
        )
        assert changed is (body == "PASS")


def test_top_level_delivery_findings_cannot_mint_provider_or_aggregate_pass(
    tmp_path: Path,
) -> None:
    module = load_module("provider_top_level_findings")
    snapshot = {
        "reviews": [
            review("coderabbitai[bot]", review_id=1),
            review("chatgpt-codex-connector[bot]", review_id=2),
        ],
        "issue_comments": [
            delivery(
                "coderabbitai[bot]",
                comment_id=3,
                app_id=347564,
                app_slug="coderabbitai",
                body="P1: unresolved top-level finding",
            )
        ],
        "review_comments": [
            delivery(
                "chatgpt-codex-connector[bot]",
                comment_id=4,
                app_id=1144995,
                app_slug="chatgpt-codex-connector",
            )
        ],
        "checks": [coderabbit_check()],
        "threads": [],
    }
    evaluator_path = tmp_path / "evaluate_ai_provider.py"
    evaluator_path.write_text("# protected evaluator\n", encoding="utf-8")
    document = module.evidence_document(
        "findings",
        repository="koios-ai/example",
        repository_id=123,
        number=42,
        head_sha=HEAD,
        base_sha=OLD,
        source_sha=OLD,
        evaluator_path=evaluator_path,
        snapshot=snapshot,
    )
    assert document["passed"] is False
    assert document["reason"] == "findings-remain-or-provider-incomplete"


def test_unresolved_provider_thread_fails_provider_and_findings() -> None:
    module = load_module("provider_threads")
    thread = {
        "isResolved": False,
        "comments": {
            "pageInfo": {"hasNextPage": False},
            "nodes": [{"author": {"login": "coderabbitai[bot]"}}],
        },
    }
    passed, details, _ = module.evaluate_provider(
        "coderabbit",
        head_sha=HEAD,
        reviews=[review("coderabbitai[bot]", review_id=1)],
        issue_comments=[
            delivery(
                "coderabbitai[bot]",
                comment_id=2,
                app_id=347564,
                app_slug="coderabbitai",
            )
        ],
        review_comments=[],
        checks=[coderabbit_check()],
        threads=[thread],
    )
    assert passed is False
    assert details["unresolved_threads"] == 1
    assert module._all_unresolved_threads([thread]) == 1


def test_review_thread_reader_completely_paginates_nested_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("provider_nested_threads")
    calls: list[str] = []

    def fake_graphql(
        query: str,
        variables: dict[str, Any],
        *,
        token: str,
    ) -> dict[str, Any]:
        del token
        calls.append(query.split("(", 1)[0])
        if query.startswith("query ReviewThreads("):
            assert variables["after"] is None
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
                                        "pageInfo": {"hasNextPage": True, "endCursor": "COMMENT-CURSOR"},
                                    },
                                }
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        assert query.startswith("query ReviewThreadComments(")
        assert variables == {"id": "THREAD-1", "after": "COMMENT-CURSOR"}
        return {
            "node": {
                "comments": {
                    "nodes": [{"author": {"login": "chatgpt-codex-connector[bot]"}}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

    monkeypatch.setattr(module, "graphql", fake_graphql)
    threads = module.review_threads("koios-ai/example", 42, token="redacted")

    assert [node["author"]["login"] for node in threads[0]["comments"]["nodes"]] == [
        "coderabbitai[bot]",
        "chatgpt-codex-connector[bot]",
    ]
    assert calls == ["query ReviewThreads", "query ReviewThreadComments"]


def test_provider_evaluator_accepts_only_same_repository_pr_targeting_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module("provider_pull_boundary")
    pull: dict[str, Any] = {
        "state": "open",
        "draft": False,
        "head": {
            "sha": HEAD,
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
        "base": {
            "sha": OLD,
            "ref": "main",
            "repo": {"id": 123, "full_name": "koios-ai/example"},
        },
    }
    observed = pull

    def fake_api_request(method: str, path: str, *, token: str) -> dict[str, Any]:
        del method, path, token
        return observed

    monkeypatch.setattr(module, "api_request", fake_api_request)
    module.validate_pull(
        "koios-ai/example",
        42,
        token="redacted",
        head_sha=HEAD,
        base_sha=OLD,
    )

    for changed in (
        {**pull, "base": {**pull["base"], "ref": "release"}},
        {
            **pull,
            "base": {
                **pull["base"],
                "repo": {"id": 123, "full_name": "attacker/fork"},
            },
        },
        {
            **pull,
            "head": {
                **pull["head"],
                "repo": {"id": 456, "full_name": "koios-ai/example"},
            },
        },
    ):
        observed = changed
        with pytest.raises(RuntimeError, match=r"changed|protected default branch"):
            module.validate_pull(
                "koios-ai/example",
                42,
                token="redacted",
                head_sha=HEAD,
                base_sha=OLD,
            )
