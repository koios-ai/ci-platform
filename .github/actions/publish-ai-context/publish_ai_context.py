"""Evidence-bound publisher for the three consumer-local AI final gates."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
from collections.abc import Mapping
from types import ModuleType
from typing import Any

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
API_URL = "https://api.github.com"
SERVER_URL = "https://github.com"
ACTION_REPOSITORY = "koios-ai/ci-platform"
DEFAULT_BRANCH = "main"
GITHUB_ACTIONS_APP = {"id": 15368, "slug": "github-actions"}
EVIDENCE_RELATIVE_PATH = pathlib.Path("ci-platform-ai-evidence", "provider-evidence.json")
PUBLISHERS = {
    (
        ".github/workflows/coderabbit-final.yml",
        "publish-coderabbit",
    ): ("AI / CodeRabbit final", "coderabbit"),
    (
        ".github/workflows/codex-final-gate.yml",
        "publish-codex",
    ): ("AI / Codex final", "codex"),
    (
        ".github/workflows/ai-findings-resolved.yml",
        "publish-findings",
    ): ("AI / findings resolved", "findings"),
}
PROVIDER_IDENTITIES = {
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


def _load_core() -> ModuleType:
    path = pathlib.Path(__file__).resolve().parents[1] / "publish-final-contexts" / "publish_final_contexts.py"
    spec = importlib.util.spec_from_file_location("ci_platform_publish_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("central publisher core is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CORE = _load_core()


def resolve_publisher(workflow_path: str, job_id: str) -> tuple[str, str]:
    try:
        return PUBLISHERS[(workflow_path, job_id)]
    except KeyError as error:
        raise ValueError("runtime is not an approved AI publisher") from error


def _exact_keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{where} fields are not the closed evidence schema")


def validate_provider_evidence(
    evidence: Mapping[str, Any],
    *,
    provider: str,
    repository: str,
    repository_id: int,
    pull_request_number: int,
    head_sha: str,
    base_sha: str,
    evaluator_result: str,
) -> bool:
    common = {
        "schema_version",
        "provider",
        "repository",
        "repository_id",
        "pull_request_number",
        "head_sha",
        "base_sha",
        "checked_at",
        "evaluator",
        "passed",
        "reason",
        "provider_evidence",
    }
    _exact_keys(evidence, common, "provider evidence")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("provider") != provider
        or evidence.get("repository") != repository
        or evidence.get("repository_id") != repository_id
        or evidence.get("pull_request_number") != pull_request_number
        or evidence.get("head_sha") != head_sha
        or evidence.get("base_sha") != base_sha
    ):
        raise ValueError("provider evidence provenance is invalid")
    checked_at = evidence.get("checked_at")
    if not isinstance(checked_at, str):
        raise ValueError("provider evidence timestamp is missing")
    try:
        parsed = dt.datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("provider evidence timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise ValueError("provider evidence timestamp has no timezone")
    evaluator = evidence.get("evaluator")
    if not isinstance(evaluator, Mapping):
        raise ValueError("provider evaluator provenance is missing")
    _exact_keys(
        evaluator,
        {"path", "sha256", "source_sha"},
        "provider evaluator",
    )
    if (
        evaluator.get("path") != ".github/ci/evaluate_ai_provider.py"
        or evaluator.get("source_sha") != base_sha
        or not DIGEST.fullmatch(str(evaluator.get("sha256", "")))
    ):
        raise ValueError("provider evaluator provenance is invalid")
    passed = evidence.get("passed")
    if not isinstance(passed, bool) or not isinstance(evidence.get("reason"), str):
        raise ValueError("provider decision is malformed")
    details = evidence.get("provider_evidence")
    if not isinstance(details, Mapping):
        raise ValueError("provider details are missing")
    if provider in PROVIDER_IDENTITIES:
        expected_identity = PROVIDER_IDENTITIES[provider]
        expected_keys = {
            *expected_identity,
            "review_id",
            "review_commit_id",
            "review_state",
            "delivery_comment_id",
            "hosted_canary_verified",
            "native_check_id",
            "native_check_conclusion",
            "review_body_sha256",
            "delivery_body_sha256",
            "unresolved_threads",
            "failure_markers",
        }
        _exact_keys(details, expected_keys, f"{provider} details")
        for key, expected in expected_identity.items():
            if details.get(key) != expected:
                raise ValueError(f"{provider} identity is invalid: {key}")
        if (
            not isinstance(details.get("review_id"), int)
            or details["review_id"] < 1
            or details.get("review_commit_id") != head_sha
            or details.get("review_state") not in {"APPROVED", "COMMENTED"}
            or not isinstance(details.get("delivery_comment_id"), int)
            or details["delivery_comment_id"] < 1
            or details.get("hosted_canary_verified") is not True
            or not DIGEST.fullmatch(str(details.get("review_body_sha256", "")))
            or not DIGEST.fullmatch(str(details.get("delivery_body_sha256", "")))
            or details.get("unresolved_threads") != 0
            or details.get("failure_markers") != []
        ):
            raise ValueError(f"{provider} current-head review evidence is invalid")
        if provider == "coderabbit" and (
            not isinstance(details.get("native_check_id"), int)
            or details["native_check_id"] < 1
            or details.get("native_check_conclusion") != "success"
        ):
            raise ValueError("CodeRabbit native check evidence is invalid")
        if provider == "codex" and (
            details.get("native_check_id") != 0 or details.get("native_check_conclusion") != ""
        ):
            raise ValueError("Codex native evidence shape is invalid")
    else:
        _exact_keys(
            details,
            {
                "coderabbit_current_head",
                "coderabbit_evidence_digest",
                "codex_current_head",
                "codex_evidence_digest",
                "unresolved_threads",
                "failure_markers",
            },
            "findings details",
        )
        if (
            details.get("coderabbit_current_head") is not True
            or details.get("codex_current_head") is not True
            or not DIGEST.fullmatch(str(details.get("coderabbit_evidence_digest", "")))
            or not DIGEST.fullmatch(str(details.get("codex_evidence_digest", "")))
            or details.get("unresolved_threads") != 0
            or details.get("failure_markers") != []
        ):
            raise ValueError("findings evidence is not fully resolved")
    return evaluator_result == "success" and passed and evidence.get("reason") == "pass"


def load_evidence(
    *,
    runner_temp: str,
    expected_digest: str,
    provider: str,
    repository: str,
    repository_id: int,
    pull_request_number: int,
    head_sha: str,
    base_sha: str,
    evaluator_result: str,
) -> tuple[bool, str]:
    if evaluator_result not in {"success", "failure", "cancelled", "skipped"}:
        raise ValueError("AI evaluator job result is malformed")
    if evaluator_result == "cancelled":
        return False, ""
    if not runner_temp:
        return False, ""
    path = pathlib.Path(runner_temp).resolve() / EVIDENCE_RELATIVE_PATH
    expected_root = pathlib.Path(runner_temp).resolve()
    if expected_root not in path.parents:
        raise ValueError("provider evidence path escaped runner temp")
    if not path.is_file():
        return False, ""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not DIGEST.fullmatch(expected_digest) or digest != expected_digest:
        return False, digest
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, digest
    if not isinstance(loaded, Mapping):
        return False, digest
    try:
        passed = validate_provider_evidence(
            loaded,
            provider=provider,
            repository=repository,
            repository_id=repository_id,
            pull_request_number=pull_request_number,
            head_sha=head_sha,
            base_sha=base_sha,
            evaluator_result=evaluator_result,
        )
    except ValueError:
        return False, digest
    return passed, digest


def validate_runtime(
    runtime: Mapping[str, str],
    pull: Mapping[str, Any],
    repository: str,
) -> tuple[str, str]:
    workflow_path = runtime.get("workflow_file_path", "")
    job_id = runtime.get("job_id", "")
    context, provider = resolve_publisher(workflow_path, job_id)
    base = pull.get("base")
    if not isinstance(base, Mapping):
        raise ValueError("pull request base metadata is absent")
    base_repo = base.get("repo")
    base_sha = base.get("sha")
    if (
        runtime.get("api_url") != API_URL
        or runtime.get("server_url") != SERVER_URL
        or runtime.get("event_name") != "pull_request_target"
        or runtime.get("action_repository") != ACTION_REPOSITORY
        or not FULL_SHA.fullmatch(runtime.get("action_ref", ""))
        or runtime.get("workflow_repository") != repository
        or runtime.get("workflow_sha") != base_sha
        or base.get("ref") != DEFAULT_BRANCH
        or runtime.get("workflow_ref") != f"{repository}/{workflow_path}@refs/heads/{DEFAULT_BRANCH}"
        or not isinstance(base_repo, Mapping)
        or str(base_repo.get("id")) != runtime.get("repository_id")
    ):
        raise ValueError("AI publisher runtime identity is invalid")
    for field in ("job_check_run_id", "run_id", "run_attempt", "repository_id"):
        value = runtime.get(field, "")
        if not value.isdecimal() or int(value) < 1:
            raise ValueError(f"AI publisher runtime identifier is invalid: {field}")
    return context, provider


def canonical_external_id(identity: Mapping[str, str]) -> str:
    expected = {
        "repository",
        "repository_id",
        "pull_request_number",
        "head_sha",
        "context",
        "provider",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "job_check_run_id",
        "evidence_digest",
        "action_ref",
        "job_id",
    }
    if set(identity) != expected:
        raise ValueError("AI external identity fields are incomplete")
    encoded = json.dumps(
        {key: identity[key] for key in sorted(identity)},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"ci-platform-ai:v1:{hashlib.sha256(encoded).hexdigest()}"


def build_payload(identity: Mapping[str, str], conclusion: str) -> dict[str, Any]:
    if conclusion not in {"success", "failure", "cancelled"}:
        raise ValueError("AI conclusion is invalid")
    context = identity.get("context", "")
    if context not in {value[0] for value in PUBLISHERS.values()}:
        raise ValueError("AI context is not approved")
    if not FULL_SHA.fullmatch(identity.get("head_sha", "")):
        raise ValueError("AI check head is malformed")
    completed = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    digest = identity.get("evidence_digest") or "unavailable"
    return {
        "name": context,
        "head_sha": identity["head_sha"],
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": completed,
        "details_url": (
            f"{SERVER_URL}/{identity['repository']}/actions/runs/"
            f"{identity['run_id']}/attempts/{identity['run_attempt']}"
        ),
        "external_id": canonical_external_id(identity),
        "output": {
            "title": f"{context}: {conclusion}",
            "summary": (
                "Consumer-local default-branch provider evaluation. "
                f"Provider: `{identity['provider']}`. "
                f"Evidence digest: `{digest}`. "
                f"Workflow SHA: `{identity['workflow_sha']}`. "
                f"Platform SHA: `{identity['action_ref']}`."
            ),
        },
    }


def _fetch_pull(
    repository: str,
    number: int,
    head_sha: str,
    *,
    token: str,
    required_label: str,
) -> Mapping[str, Any]:
    pull = CORE.api_request(
        "GET",
        f"/repos/{repository}/pulls/{number}",
        token=token,
    )
    if not isinstance(pull, Mapping):
        raise RuntimeError("GitHub returned malformed pull request metadata")
    if pull.get("number") != number:
        raise RuntimeError("GitHub returned another pull request")
    head = pull.get("head")
    base = pull.get("base")
    head_repo = head.get("repo") if isinstance(head, Mapping) else None
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if isinstance(base, Mapping) and base.get("ref") != DEFAULT_BRANCH:
        raise ValueError("AI candidate does not target the protected default branch")
    if (
        pull.get("state") != "open"
        or pull.get("draft") is not False
        or not isinstance(head, Mapping)
        or head.get("sha") != head_sha
        or not isinstance(head_repo, Mapping)
        or head_repo.get("full_name") != repository
        or not isinstance(base, Mapping)
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != repository
        or not isinstance(head_repo.get("id"), int)
        or head_repo.get("id") != base_repo.get("id")
    ):
        raise ValueError("AI candidate changed or is not same-repository")
    labels = {label.get("name") for label in pull.get("labels", []) if isinstance(label, Mapping)}
    if required_label not in labels:
        raise ValueError(f"required AI cadence label is absent: {required_label}")
    return pull


def _validate_current_run(
    run: Mapping[str, Any],
    *,
    runtime: Mapping[str, str],
    pull: Mapping[str, Any],
    repository: str,
    number: int,
) -> None:
    CORE._validate_current_run(
        run,
        runtime=runtime,
        pull=pull,
        repository=repository,
        number=number,
    )


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
    ):
        raise ValueError("trusted AI publication inputs are unavailable")
    number = int(raw_number)
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
    context, provider = resolve_publisher(runtime["workflow_file_path"], runtime["job_id"])
    label = "ai-review-ready"
    pull = _fetch_pull(
        repository,
        number,
        head_sha,
        token=token,
        required_label=label,
    )
    validated_context, validated_provider = validate_runtime(runtime, pull, repository)
    if (validated_context, validated_provider) != (context, provider):
        raise ValueError("AI publisher tuple changed during validation")
    run = CORE.api_request(
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
    CORE.assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )
    evaluator_result = os.environ.get("INPUT_EVALUATION_RESULT", "")
    passed, evidence_digest = load_evidence(
        runner_temp=os.environ.get("RUNNER_TEMP", ""),
        expected_digest=os.environ.get("INPUT_EXPECTED_EVIDENCE_DIGEST", ""),
        provider=provider,
        repository=repository,
        repository_id=int(runtime["repository_id"]),
        pull_request_number=number,
        head_sha=head_sha,
        base_sha=str(pull["base"]["sha"]),
        evaluator_result=evaluator_result,
    )
    conclusion = "cancelled" if evaluator_result == "cancelled" else "success" if passed else "failure"
    identity = {
        "repository": repository,
        "repository_id": runtime["repository_id"],
        "pull_request_number": str(number),
        "head_sha": head_sha,
        "context": context,
        "provider": provider,
        "workflow_ref": runtime["workflow_ref"],
        "workflow_sha": runtime["workflow_sha"],
        "run_id": runtime["run_id"],
        "run_attempt": runtime["run_attempt"],
        "job_check_run_id": runtime["job_check_run_id"],
        "evidence_digest": evidence_digest,
        "action_ref": runtime["action_ref"],
        "job_id": runtime["job_id"],
    }
    payload = build_payload(identity, conclusion)
    pull = _fetch_pull(
        repository,
        number,
        head_sha,
        token=token,
        required_label=label,
    )
    CORE.assert_newest_prt_attempt(
        run,
        pull=pull,
        repository=repository,
        token=token,
    )
    check_id = CORE._upsert_check(repository, payload, token=token)
    try:
        pull = _fetch_pull(
            repository,
            number,
            head_sha,
            token=token,
            required_label=label,
        )
        CORE.assert_newest_prt_attempt(
            run,
            pull=pull,
            repository=repository,
            token=token,
        )
    except (ValueError, RuntimeError):
        CORE._cancel_written_check(
            repository,
            check_id,
            payload,
            token=token,
        )
        raise
    readback = CORE.api_request(
        "GET",
        f"/repos/{repository}/check-runs/{check_id}",
        token=token,
    )
    if not isinstance(readback, Mapping):
        raise RuntimeError("GitHub returned malformed AI check readback")
    CORE.validate_written_check(readback, payload)
    try:
        pull = _fetch_pull(
            repository,
            number,
            head_sha,
            token=token,
            required_label=label,
        )
        CORE.assert_newest_prt_attempt(
            run,
            pull=pull,
            repository=repository,
            token=token,
        )
    except (ValueError, RuntimeError):
        CORE._cancel_written_check(
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
