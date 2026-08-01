from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / ".github" / "actions" / "publish-final-contexts" / "publish_final_contexts.py"
HEAD_SHA = "a" * 40
CONFIG_BLOB_SHA = "b" * 40
REPOSITORY = "koios-ai/example"
BOT = {"id": 42547082, "login": "deepsource-io[bot]", "type": "Bot"}

CONFIG = b"""\
version = 1

[[analyzers]]
name = "python"
enabled = true

  [analyzers.meta]
  dependency_file_paths = [
    "requirements-core-next.txt",
    "requirements-compat-ag.txt",
  ]

[[analyzers]]
name = "test-coverage"
enabled = false

[[analyzers]]
name = "secrets"
enabled = true
"""


def load_publisher(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, PUBLISHER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def status(
    context: str,
    state: str,
    identifier: int,
    *,
    creator: dict[str, Any] | None = None,
    target_url: str | None = None,
) -> dict[str, Any]:
    suffix = {
        "DeepSource: Secrets": "secrets/",
        "DeepSource: requirements-core-next.txt": "sca/core/",
        "DeepSource: requirements-compat-ag.txt": "sca/compat/",
        "DeepSource: Test coverage": "coverage/",
        "DeepSource: AI Review": "",
    }.get(context, "analyzer/")
    return {
        "id": identifier,
        "context": context,
        "state": state,
        "creator": BOT if creator is None else creator,
        "target_url": (
            f"https://app.deepsource.com/gh/{REPOSITORY}/run/00000000-0000-4000-8000-000000000001/{suffix}"
            if target_url is None
            else target_url
        ),
    }


def passing_statuses() -> list[dict[str, Any]]:
    return [
        status("DeepSource: Secrets", "success", 103),
        status("DeepSource: requirements-core-next.txt", "success", 102),
        status("DeepSource: requirements-compat-ag.txt", "success", 101),
        status("DeepSource: AI Review", "pending", 100),
        status("DeepSource: Test coverage", "pending", 99),
        # Older state for the same context must not override the newest record.
        status("DeepSource: requirements-core-next.txt", "pending", 98),
    ]


def analysis_check(
    identifier: int = 202,
    *,
    status_value: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "name": "DeepSource analysis",
        "head_sha": HEAD_SHA,
        "status": status_value,
        "conclusion": conclusion,
        "app": {"id": 16372, "slug": "deepsource-io"},
    }


def test_deepsource_policy_requires_configured_dependencies_and_ignores_disabled_noise() -> None:
    module = load_publisher("publisher_deepsource_pass")
    policy = module.parse_deepsource_policy(CONFIG, CONFIG_BLOB_SHA)

    assert policy.config_blob_sha == CONFIG_BLOB_SHA
    assert policy.test_coverage_enabled is False
    assert policy.dependency_contexts == frozenset(
        {
            "DeepSource: requirements-core-next.txt",
            "DeepSource: requirements-compat-ag.txt",
        }
    )

    result = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [analysis_check()],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert result.state == "passed"
    assert result.passing is True
    assert len(result.evidence_digest) == 64


@pytest.mark.parametrize(
    ("mutate", "expected_state"),
    [
        (
            lambda values: [item for item in values if item["context"] != "DeepSource: requirements-compat-ag.txt"],
            "pending",
        ),
        (
            lambda values: [
                (
                    {**item, "state": "pending", "id": 1000}
                    if item["context"] == "DeepSource: requirements-core-next.txt"
                    else item
                )
                for item in values
            ],
            "pending",
        ),
        (
            lambda values: [
                ({**item, "state": "failure", "id": 1000} if item["context"] == "DeepSource: AI Review" else item)
                for item in values
            ],
            "failed",
        ),
        (
            lambda values: [
                (
                    {
                        **item,
                        "creator": {
                            "id": 1,
                            "login": "attacker[bot]",
                            "type": "Bot",
                        },
                    }
                    if item["context"] == "DeepSource: Secrets"
                    else item
                )
                for item in values
            ],
            "failed",
        ),
        (
            lambda values: [
                (
                    {**item, "target_url": "https://attacker.invalid/result"}
                    if item["context"] == "DeepSource: Secrets"
                    else item
                )
                for item in values
            ],
            "failed",
        ),
    ],
)
def test_deepsource_status_evidence_fails_closed(
    mutate: Any,
    expected_state: str,
) -> None:
    module = load_publisher(f"publisher_deepsource_{expected_state}")
    policy = module.parse_deepsource_policy(CONFIG, CONFIG_BLOB_SHA)
    result = module.evaluate_deepsource_signals(
        policy,
        mutate(passing_statuses()),
        [analysis_check()],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert result.state == expected_state
    assert result.passing is False


def test_native_deepsource_analysis_is_mandatory_and_github_wrapper_is_ignored() -> None:
    module = load_publisher("publisher_deepsource_check")
    policy = module.parse_deepsource_policy(CONFIG, CONFIG_BLOB_SHA)
    wrapper = {
        "id": 201,
        "name": "Quality / deepsource",
        "head_sha": HEAD_SHA,
        "status": "completed",
        "conclusion": "failure",
        "app": {"id": 15368, "slug": "github-actions"},
    }
    missing = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [wrapper],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert missing.state == "pending"

    passed = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [wrapper, analysis_check()],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert passed.state == "passed"

    failed = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [wrapper, analysis_check(conclusion="failure")],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert failed.state == "failed"


def test_deepsource_analysis_uses_unique_newest_exact_head_signal() -> None:
    module = load_publisher("publisher_deepsource_newest")
    policy = module.parse_deepsource_policy(CONFIG, CONFIG_BLOB_SHA)

    passed = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [
            analysis_check(201, conclusion="failure"),
            analysis_check(202, conclusion="success"),
        ],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert passed.state == "passed"

    duplicate = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [
            analysis_check(202, conclusion="failure"),
            analysis_check(202, conclusion="success"),
        ],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert duplicate.state == "failed"

    wrong_head = analysis_check()
    wrong_head["head_sha"] = "c" * 40
    malformed = module.evaluate_deepsource_signals(
        policy,
        passing_statuses(),
        [wrong_head],
        repository=REPOSITORY,
        head_sha=HEAD_SHA,
    )
    assert malformed.state == "failed"


def test_deepsource_config_parser_is_closed_and_fail_closed() -> None:
    module = load_publisher("publisher_deepsource_config")
    with pytest.raises(ValueError):
        module.parse_deepsource_policy(b"version = [broken", CONFIG_BLOB_SHA)
    with pytest.raises(ValueError):
        module.parse_deepsource_policy(b"version = 2\n", CONFIG_BLOB_SHA)
    with pytest.raises(ValueError):
        module.parse_deepsource_policy(CONFIG, "not-a-sha")
