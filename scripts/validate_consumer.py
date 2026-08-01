"""Validate a consumer repository against the immutable CI platform contract."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping
from typing import Any, cast

import yaml
from test_policy import POLICY_PATH as TEST_POLICY_PATH
from test_policy import load_policy_file

SHA = re.compile(r"^[0-9a-f]{40}$")
CODERABBIT_CONFIG_PATH = ".coderabbit.yaml"
PLATFORM_REPOSITORY = "koios-ai/ci-platform"
PLATFORM_WORKFLOW = ".github/workflows/required.yml"
PLATFORM_PREFIX = f"{PLATFORM_REPOSITORY}/"
REQUIRED_CONTEXTS = {
    "ci / required",
    "security / required",
    "coverage / required",
    "ai / coderabbit final",
    "ai / codex final",
    "ai / findings resolved",
}
UNTRUSTED_EVENTS = {
    "merge_group",
    "pull_request",
    "push",
    "workflow_call",
    "workflow_dispatch",
}
MANAGED_WORKFLOWS = {
    ".github/workflows/final-required.yml",
    ".github/workflows/coderabbit-final.yml",
    ".github/workflows/codex-final-gate.yml",
    ".github/workflows/ai-findings-resolved.yml",
    ".github/workflows/invalidate-final-labels.yml",
    ".github/workflows/final-subject-v1.yml",
    ".github/workflows/finalize-python-v1.yml",
    ".github/workflows/resume-finalizer-v1.yml",
}
TRUSTED_DISPATCH_WORKFLOWS = {
    ".github/workflows/final-subject-v1.yml",
    ".github/workflows/finalize-python-v1.yml",
}
BOT_BOUND_DISPATCH_WORKFLOWS = TRUSTED_DISPATCH_WORKFLOWS
SUBJECT_COMPLETION_WORKFLOW = ".github/workflows/resume-finalizer-v1.yml"
TRUSTED_DISPATCH_CONDITION = "github.actor == 'github-actions[bot]' && github.triggering_actor == 'github-actions[bot]'"
EXPECTED_CHECK_PUBLISHERS = {
    (".github/workflows/final-required.yml", "publish-security"),
    (".github/workflows/final-required.yml", "publish-coverage"),
    (".github/workflows/coderabbit-final.yml", "publish-coderabbit"),
    (".github/workflows/codex-final-gate.yml", "publish-codex"),
    (".github/workflows/ai-findings-resolved.yml", "publish-findings"),
}
PLATFORM_ENTRYPOINTS = {
    ".github/workflows/reusable-final.yml",
    ".github/actions/final-preflight",
    ".github/actions/invalidate-final-labels",
    ".github/actions/verify-evidence",
    ".github/actions/publish-final-contexts",
    ".github/actions/promote-ai-review",
    ".github/actions/publish-ai-context",
    ".github/actions/dispatch-finalizer",
}
ROLE_REFERENCES = {
    "final-preflight": {
        "koios-ai/ci-platform/.github/actions/final-preflight",
    },
    "coverage-uploader": {
        "actions/download-artifact",
        "koios-ai/ci-platform/.github/actions/verify-evidence",
        "codecov/codecov-action",
    },
    "final-context-publisher": {
        "koios-ai/ci-platform/.github/actions/publish-final-contexts",
    },
    "security-context-publisher": {
        "koios-ai/ci-platform/.github/actions/publish-final-contexts",
    },
    "ai-review-promoter": {
        "koios-ai/ci-platform/.github/actions/promote-ai-review",
    },
    "ai-evaluator": {
        "actions/checkout",
        "actions/upload-artifact",
    },
    "ai-context-publisher": {
        "actions/download-artifact",
        "koios-ai/ci-platform/.github/actions/publish-ai-context",
    },
    "label-controller": {
        "koios-ai/ci-platform/.github/actions/invalidate-final-labels",
    },
    "finalizer-dispatcher": {
        "koios-ai/ci-platform/.github/actions/dispatch-finalizer",
    },
    "exact-head-finalizer": {
        "actions/checkout",
    },
}
ROLE_PERMISSIONS = {
    "final-preflight": {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "pull-requests": "read",
    },
    "coverage-uploader": {
        "actions": "read",
        "contents": "read",
        "id-token": "write",
    },
    "final-context-publisher": {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
    },
    "security-context-publisher": {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
        "statuses": "read",
    },
    "ai-review-promoter": {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    },
    "ai-evaluator": {
        "checks": "read",
        "contents": "read",
        "pull-requests": "read",
        "statuses": "read",
    },
    "ai-context-publisher": {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
    },
    "label-controller": {
        "issues": "write",
        "pull-requests": "read",
    },
    "finalizer-dispatcher": {
        "actions": "write",
        "contents": "read",
    },
    "exact-head-finalizer": {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    },
}


class ActionsLoader(yaml.SafeLoader):
    """YAML 1.2-like loader that leaves the workflow key ``on`` intact."""


ActionsLoader.yaml_implicit_resolvers = {
    key: list(value) for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


for first_char, resolvers in list(ActionsLoader.yaml_implicit_resolvers.items()):
    ActionsLoader.yaml_implicit_resolvers[first_char] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
add_actions_resolver = cast(Callable[[str, re.Pattern[str], list[str]], None], ActionsLoader.add_implicit_resolver)
add_actions_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _require_sha(value: str, name: str) -> str:
    if not SHA.fullmatch(value):
        raise ValueError(f"{name} is not a full lowercase commit SHA")
    return value


def parse_actions_yaml(raw: str) -> Any:
    """Parse Actions YAML through the restricted SafeLoader subclass."""
    loader = ActionsLoader(raw)
    try:
        return loader.get_single_data()
    finally:
        cast(Callable[[], None], loader.dispose)()


def load_yaml(path: pathlib.Path) -> dict[str, Any]:
    loaded = parse_actions_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"malformed YAML mapping: {path}")
    return loaded


def event_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, Mapping):
        return {str(item) for item in value}
    return set()


def _event_configuration(workflow: Mapping[str, Any], event: str) -> Any:
    configured = workflow.get("on")
    if isinstance(configured, Mapping):
        return configured.get(event)
    return None


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _direct_trusted_workflow_run_guard(job: Mapping[str, Any]) -> bool:
    condition = normalized_name(job.get("if", ""))
    required = (
        "github.event.workflow_run.conclusion",
        "success",
        "github.event.workflow_run.event",
        "push",
        "github.event.workflow_run.head_branch",
        "main",
    )
    return all(marker in condition for marker in required)


def _needs(job: Mapping[str, Any]) -> set[str]:
    value = job.get("needs", [])
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _guarded_by_trusted_workflow_run(
    job_id: str,
    jobs: Mapping[str, Any],
    *,
    seen: set[str] | None = None,
) -> bool:
    seen = set() if seen is None else seen
    if job_id in seen:
        return False
    seen.add(job_id)
    job = jobs.get(job_id)
    if not isinstance(job, Mapping):
        return False
    if _direct_trusted_workflow_run_guard(job):
        return True
    return any(_guarded_by_trusted_workflow_run(parent, jobs, seen=set(seen)) for parent in _needs(job))


def _trusted_workflow_run_head(
    workflow: Mapping[str, Any],
    job_id: str,
    jobs: Mapping[str, Any],
) -> bool:
    configuration = _event_configuration(workflow, "workflow_run")
    if not isinstance(configuration, Mapping):
        return False
    if _string_set(configuration.get("types")) != {"completed"}:
        return False
    if _string_set(configuration.get("branches")) != {"main"}:
        return False
    return _guarded_by_trusted_workflow_run(job_id, jobs)


def permission_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, str):
        return {"*": value}
    if not isinstance(value, Mapping):
        raise ValueError("permissions must be a mapping")
    return {str(key): str(setting) for key, setting in value.items()}


def iter_steps(job: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    steps = job.get("steps", [])
    if steps is None:
        return []
    if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
        raise ValueError("workflow has malformed steps")
    return list(steps)


def normalized_name(value: Any) -> str:
    text = str(value).lower()
    text = text.replace("${{", "").replace("}}", "")
    text = text.replace("'", "").replace('"', "")
    return re.sub(r"\s+", " ", text).strip()


def role_for(job: Mapping[str, Any]) -> str:
    env = job.get("env")
    return str(env.get("CI_PLATFORM_ROLE", "")) if isinstance(env, Mapping) else ""


def references(job: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    if "uses" in job:
        result.append(str(job["uses"]))
    result.extend(str(step["uses"]) for step in iter_steps(job) if "uses" in step)
    return result


def reference_locators(values: Iterable[str]) -> set[str]:
    return {value.rsplit("@", 1)[0] if "@" in value else value for value in values}


def _platform_reference(
    reference: str,
    *,
    lock_sha: str | None,
    where: pathlib.Path,
) -> None:
    locator, pin = reference.rsplit("@", 1)
    lower_locator = locator.lower()
    if lower_locator.startswith(PLATFORM_PREFIX.lower()):
        if not locator.startswith(PLATFORM_PREFIX):
            raise ValueError(f"case-variant platform prefix in {where}")
        entrypoint = locator.removeprefix(PLATFORM_PREFIX)
        if entrypoint not in PLATFORM_ENTRYPOINTS:
            raise ValueError(f"unapproved platform entrypoint in {where}")
        if lock_sha is None or pin != lock_sha:
            raise ValueError(f"platform reference does not match lock in {where}")


def validate_reference(
    reference: str,
    *,
    root: pathlib.Path,
    lock_sha: str | None,
    where: pathlib.Path,
    visited: set[pathlib.Path],
) -> None:
    if reference.startswith("./"):
        relative = pathlib.PurePosixPath(reference.removeprefix("./"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe local action reference in {where}")
        action_dir = root.joinpath(*relative.parts)
        descriptors = [
            action_dir / "action.yml",
            action_dir / "action.yaml",
        ]
        descriptor = next((path for path in descriptors if path.is_file()), None)
        if descriptor is None:
            raise ValueError(f"missing local action descriptor in {where}")
        resolved = descriptor.resolve()
        if resolved in visited:
            return
        visited.add(resolved)
        action = load_yaml(descriptor)
        runs = action.get("runs")
        steps = runs.get("steps", []) if isinstance(runs, Mapping) else []
        if not isinstance(steps, list):
            raise ValueError(f"malformed local action steps: {descriptor}")
        for step in steps:
            if not isinstance(step, Mapping):
                raise ValueError(f"malformed local action step: {descriptor}")
            nested = step.get("uses")
            if nested:
                try:
                    validate_reference(
                        str(nested),
                        root=root,
                        lock_sha=lock_sha,
                        where=descriptor,
                        visited=visited,
                    )
                except ValueError as error:
                    if "mutable action or workflow reference" in str(error):
                        raise ValueError(f"mutable nested action reference in {descriptor}") from error
                    raise
        return
    if "@" not in reference:
        raise ValueError(f"mutable action or workflow reference in {where}")
    pin = reference.rsplit("@", 1)[1]
    if not SHA.fullmatch(pin):
        raise ValueError(f"mutable action or workflow reference in {where}")
    _platform_reference(reference, lock_sha=lock_sha, where=where)


def _contains_sensitive_reference(job: Mapping[str, Any]) -> tuple[bool, bool]:
    serialized = json.dumps(job)
    secret = bool(re.search(r"(?:\bsecrets\b|tojson\s*\(\s*secrets\s*\))", serialized, re.I))
    token = bool(
        re.search(
            r"github(?:\.|\[['\"])(?:token|TOKEN)(?:['\"]\])?",
            serialized,
            re.I,
        )
    )
    return secret, token


def _assert_read_only_permissions(value: Any, where: str) -> None:
    parsed = permission_map(value)
    if not parsed or "*" in parsed:
        raise ValueError(f"missing explicit scoped read permissions in {where}")
    for scope, setting in parsed.items():
        if setting not in {"read", "none"}:
            raise ValueError(f"privileged permission {scope}:{setting} in {where}")
        if scope == "id-token" and setting != "none":
            raise ValueError(f"OIDC in untrusted job {where}")


def _canonical_templates(platform_root: pathlib.Path, lock_sha: str) -> dict[str, Any]:
    template_root = platform_root / "templates" / "consumer" / ".github" / "workflows"
    canonical: dict[str, Any] = {}
    for workflow_path in MANAGED_WORKFLOWS:
        path = template_root / pathlib.PurePosixPath(workflow_path).name
        raw = path.read_text(encoding="utf-8").replace("__CI_PLATFORM_FULL_SHA__", lock_sha)
        loaded = parse_actions_yaml(raw)
        if not isinstance(loaded, dict):
            raise RuntimeError(f"platform template is malformed: {path}")
        canonical[workflow_path] = loaded
    return canonical


def _validate_managed_tree(
    root: pathlib.Path,
    *,
    platform_root: pathlib.Path,
    lock_sha: str,
    observed_paths: set[str],
) -> None:
    if observed_paths != MANAGED_WORKFLOWS:
        raise ValueError("managed consumer does not contain the exact controller workflows")
    canonical = _canonical_templates(platform_root, lock_sha)
    for workflow_path in MANAGED_WORKFLOWS:
        actual = load_yaml(root / pathlib.PurePosixPath(workflow_path))
        if actual != canonical[workflow_path]:
            raise ValueError(f"managed consumer workflow differs from platform template: {workflow_path}")
    target_evaluator = root / ".github" / "ci" / "evaluate_ai_provider.py"
    platform_evaluator = platform_root / "templates" / "consumer" / ".github" / "ci" / "evaluate_ai_provider.py"
    if not target_evaluator.is_file() or target_evaluator.read_text(encoding="utf-8").replace(
        "\r\n", "\n"
    ) != platform_evaluator.read_text(encoding="utf-8").replace("\r\n", "\n"):
        raise ValueError("consumer-local provider evaluator is absent or altered")
    target_coderabbit = root / CODERABBIT_CONFIG_PATH
    platform_coderabbit = platform_root / "templates" / "consumer" / CODERABBIT_CONFIG_PATH
    if not target_coderabbit.is_file() or target_coderabbit.read_text(encoding="utf-8").replace(
        "\r\n", "\n"
    ) != platform_coderabbit.read_text(encoding="utf-8").replace("\r\n", "\n"):
        raise ValueError("consumer CodeRabbit configuration is absent or altered")


def _validate_role(
    *,
    role: str,
    job: Mapping[str, Any],
    values: list[str],
    permissions: dict[str, str],
    workflow_path: str,
    job_id: str,
) -> None:
    where = f"{workflow_path}:{job_id}"
    expected_references = ROLE_REFERENCES.get(role)
    if expected_references is None or reference_locators(values) != expected_references:
        raise ValueError(f"unapproved action set in privileged role {where}")
    if "uses" in job:
        raise ValueError(f"metadata role delegates to reusable workflow in {where}")
    if permission_map(permissions) != ROLE_PERMISSIONS[role]:
        raise ValueError(f"unexpected permissions in {where}")
    secret, token = _contains_sensitive_reference(job)
    if secret:
        raise ValueError(f"secret reaches metadata controller {where}")
    if role == "coverage-uploader":
        if token:
            raise ValueError(f"token reaches OIDC uploader {where}")
    elif not token:
        raise ValueError(f"metadata controller lacks bounded token in {where}")
    steps = iter_steps(job)
    if role not in {"ai-evaluator", "exact-head-finalizer"} and any(str(step.get("run", "")).strip() for step in steps):
        raise ValueError(f"inline shell in metadata role {where}")
    for step in steps:
        reference = str(step.get("uses", ""))
        if reference.startswith("./"):
            raise ValueError(f"PR-controlled local action in {where}")
        if reference.startswith("actions/checkout@"):
            checkout = step.get("with")
            ref = checkout.get("ref") if isinstance(checkout, Mapping) else None
            repository = checkout.get("repository") if isinstance(checkout, Mapping) else None
            if role == "exact-head-finalizer":
                if repository != PLATFORM_REPOSITORY or not isinstance(ref, str) or not SHA.fullmatch(ref):
                    raise ValueError(f"finalizer checkout is not the immutable platform SHA in {where}")
            elif ref != "${{ github.event.pull_request.base.sha }}":
                raise ValueError(f"metadata checkout is not exact base SHA in {where}")


def validate_consumer(
    root: pathlib.Path,
    *,
    head_sha: str,
    base_sha: str,
    platform_root: pathlib.Path,
) -> None:
    _require_sha(head_sha, "event head")
    _require_sha(base_sha, "event base")
    root = root.resolve()
    platform_root = platform_root.resolve()
    if not root.is_dir():
        raise ValueError("consumer root is unavailable")
    git_dir = root / ".git"
    if git_dir.exists():
        actual_head = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        if actual_head != head_sha:
            raise ValueError("consumer checkout is not the exact event head")

    lock_path = root / ".github" / "ci-platform.lock.json"
    lock_sha: str | None = None
    if lock_path.is_file():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        if not isinstance(lock, Mapping):
            raise ValueError("ci-platform lock is malformed")
        lock_sha = str(lock.get("sha", ""))
        _require_sha(lock_sha, "ci-platform lock SHA")
        if lock.get("contract_version") != 1 or set(lock) != {
            "sha",
            "contract_version",
        }:
            raise ValueError("ci-platform lock contract is not exactly version 1")
        platform_commit = subprocess.check_output(
            ["git", "-C", str(platform_root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        if lock_sha != platform_commit:
            raise ValueError("ci-platform lock does not match the current required-workflow platform SHA")

    workflows_root = root / ".github" / "workflows"
    observed_managed: set[str] = set()
    observed_publishers: set[tuple[str, str]] = set()
    visited_actions: set[pathlib.Path] = set()
    for path in sorted(workflows_root.glob("*.y*ml")):
        workflow_path = path.relative_to(root).as_posix()
        if workflow_path in MANAGED_WORKFLOWS:
            observed_managed.add(workflow_path)
        raw = path.read_text(encoding="utf-8")
        if re.search(r"secrets\s*:\s*inherit", raw, re.I):
            raise ValueError(f"secret inheritance in {workflow_path}")
        if "CODECOV_TOKEN" in raw or "CODERABBIT_AUTOFIX_TOKEN" in raw:
            raise ValueError(f"forbidden token in {workflow_path}")
        document = load_yaml(path)
        events = event_names(document.get("on"))
        if not events:
            raise ValueError(f"workflow has no supported event: {workflow_path}")
        trusted_dispatch = workflow_path in TRUSTED_DISPATCH_WORKFLOWS and events == {"workflow_dispatch"}
        subject_completion = workflow_path == SUBJECT_COMPLETION_WORKFLOW
        if subject_completion:
            configuration = _event_configuration(document, "workflow_run")
            if (
                events != {"workflow_run"}
                or not isinstance(configuration, Mapping)
                or _string_set(configuration.get("workflows")) != {"Exact-head final subject"}
                or _string_set(configuration.get("branches")) != {"main"}
                or _string_set(configuration.get("types")) != {"completed"}
            ):
                raise ValueError("resume finalizer is not bound to exact completed subject runs")
        untrusted = bool(events & UNTRUSTED_EVENTS) and not trusted_dispatch
        # Every event outside the closed no-secret set is a protected controller
        # event and therefore must be one of the exact managed templates.
        privileged = bool(events - UNTRUSTED_EVENTS) or trusted_dispatch
        root_permissions = document.get("permissions", {})
        if "*" in permission_map(root_permissions):
            raise ValueError(f"wildcard permissions are forbidden in {workflow_path}")
        if privileged and workflow_path not in MANAGED_WORKFLOWS:
            raise ValueError(f"unmanaged privileged workflow is outside the closed controller set: {workflow_path}")
        jobs = document.get("jobs")
        if not isinstance(jobs, Mapping):
            raise ValueError(f"workflow has no jobs mapping: {workflow_path}")
        for raw_job_id, raw_job in jobs.items():
            job_id = str(raw_job_id)
            if not isinstance(raw_job, Mapping):
                raise ValueError(f"malformed job {job_id} in {workflow_path}")
            job = raw_job
            where = f"{workflow_path}:{job_id}"
            if trusted_dispatch and workflow_path in BOT_BOUND_DISPATCH_WORKFLOWS:
                condition = str(job.get("if", ""))
                if not all(
                    marker in condition
                    for marker in (
                        "github.actor == 'github-actions[bot]'",
                        "github.triggering_actor == 'github-actions[bot]'",
                    )
                ):
                    raise ValueError(f"trusted workflow_dispatch job lacks exact bot binding in {where}")
            if subject_completion:
                condition = normalized_name(job.get("if", ""))
                required = (
                    "github.run_attempt == 1",
                    "github.actor == github-actions[bot]",
                    "github.triggering_actor == github-actions[bot]",
                    "github.event.workflow_run.conclusion == success",
                    "github.event.workflow_run.event == workflow_dispatch",
                    "github.event.workflow_run.head_branch == main",
                )
                if not all(marker in condition for marker in required):
                    raise ValueError(f"resume finalizer lacks exact completed-subject binding in {where}")
            permissions = permission_map(job.get("permissions", root_permissions))
            if "*" in permissions:
                raise ValueError(f"wildcard permissions are forbidden in {where}")
            if permissions.get("statuses") == "write":
                raise ValueError(f"statuses:write is forbidden in {where}")
            if permissions.get("checks") == "write":
                publisher = (workflow_path, job_id)
                if publisher not in EXPECTED_CHECK_PUBLISHERS:
                    raise ValueError(f"checks:write outside exact publisher tuple in {where}")
                observed_publishers.add(publisher)
            job_name = job.get("name", "")
            if not isinstance(job_name, str) or "${{" in job_name or "}}" in job_name:
                raise ValueError(f"dynamic job name is forbidden in {where}")
            if normalized_name(job_name) in REQUIRED_CONTEXTS:
                raise ValueError(f"target workflow spoofs required job context in {workflow_path}")
            if job.get("environment") is not None and untrusted:
                raise ValueError(f"protected environment in PR-triggerable job {where}")
            if "uses" in job and untrusted:
                raise ValueError(f"external reusable workflow job is forbidden in untrusted workflow: {where}")

            values = references(job)
            for reference in values:
                validate_reference(
                    reference,
                    root=root,
                    lock_sha=lock_sha,
                    where=path,
                    visited=visited_actions,
                )
            serialized = json.dumps(job).lower()
            shell_text = "\n".join(str(step.get("run", "")).lower() for step in iter_steps(job))
            secret, token = _contains_sensitive_reference(job)
            cache = any(reference.lower().startswith("actions/cache@") for reference in values) or any(
                isinstance(step.get("with"), Mapping) and "cache" in step["with"] for step in iter_steps(job)
            )
            artifact_download = any(reference.lower().startswith("actions/download-artifact@") for reference in values)
            check_mint = "check-runs" in serialized or "statuses/" in serialized
            pull_request_head_import = any(
                marker in shell_text
                for marker in (
                    "refs/pull/",
                    "pull_request.head",
                    "fetch_head",
                    "gh pr checkout",
                )
            )
            workflow_run_head_import = "workflow_run.head_sha" in shell_text
            for step in iter_steps(job):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    checkout = step.get("with")
                    ref = str(checkout.get("ref", "") if isinstance(checkout, Mapping) else "").lower()
                    if any(
                        marker in ref
                        for marker in (
                            "pull_request.head",
                            "refs/pull/",
                        )
                    ):
                        pull_request_head_import = True
                    if "workflow_run.head_sha" in ref:
                        workflow_run_head_import = True

            if untrusted:
                _assert_read_only_permissions(permissions, where)
                if secret or token:
                    raise ValueError(f"token or secret reaches PR-code job {where}")
                if cache:
                    raise ValueError(f"cache use in untrusted job {where}")
                if artifact_download:
                    raise ValueError(f"untrusted artifact download in {where}")
                if check_mint:
                    raise ValueError(f"required-check minting in untrusted job {where}")

            reserved_role = role_for(job)
            job_uses = str(job.get("uses", ""))
            if workflow_path not in MANAGED_WORKFLOWS:
                if reserved_role:
                    raise ValueError(f"reserved CI platform role outside managed workflow in {where}")
                if ".github/workflows/reusable-final.yml" in job_uses:
                    raise ValueError(f"reusable final is outside exact controller in {where}")

            if privileged and workflow_path in MANAGED_WORKFLOWS:
                role = reserved_role
                if ".github/workflows/reusable-final.yml" in job_uses:
                    if workflow_path not in {
                        ".github/workflows/final-required.yml",
                        ".github/workflows/final-subject-v1.yml",
                    }:
                        raise ValueError(f"reusable final is outside exact controller in {where}")
                elif role not in ROLE_REFERENCES:
                    raise ValueError(f"unclassified privileged job {where}")
                if role:
                    _validate_role(
                        role=role,
                        job=job,
                        values=values,
                        permissions=permissions,
                        workflow_path=workflow_path,
                        job_id=job_id,
                    )
                    if pull_request_head_import or workflow_run_head_import:
                        raise ValueError(f"PR-head import in metadata role {where}")
                    if cache:
                        raise ValueError(f"cache use in metadata role {where}")
            if check_mint and role_for(job) not in {
                "final-context-publisher",
                "security-context-publisher",
                "ai-context-publisher",
            }:
                raise ValueError(f"required-check minting outside publisher in {where}")

    if observed_managed:
        if lock_sha is None:
            raise ValueError("managed consumer has no ci-platform lock")
        load_policy_file(
            root / pathlib.PurePosixPath(TEST_POLICY_PATH),
            root=root,
        )
        _validate_managed_tree(
            root,
            platform_root=platform_root,
            lock_sha=lock_sha,
            observed_paths=observed_managed,
        )
        if observed_publishers != EXPECTED_CHECK_PUBLISHERS:
            raise ValueError("managed consumer does not contain exactly five check publishers")


def validate_platform_identity(
    *,
    platform_root: pathlib.Path,
    repository: str,
    sha: str,
    workflow_ref: str,
    workflow_file_path: str,
) -> None:
    _require_sha(sha, "platform workflow SHA")
    expected_prefix = f"{PLATFORM_REPOSITORY}/{PLATFORM_WORKFLOW}@"
    workflow_ref_value = workflow_ref.removeprefix(expected_prefix) if workflow_ref.startswith(expected_prefix) else ""
    if (
        repository != PLATFORM_REPOSITORY
        or workflow_file_path != PLATFORM_WORKFLOW
        or workflow_ref_value != "refs/heads/main"
    ):
        raise ValueError("platform workflow runtime identity is invalid")
    actual = subprocess.check_output(
        ["git", "-C", str(platform_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if actual != sha:
        raise ValueError("platform checkout is not job.workflow_sha")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--platform-repository", required=True)
    parser.add_argument("--platform-sha", required=True)
    parser.add_argument("--platform-ref", required=True)
    parser.add_argument("--platform-file-path", required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    platform_root = pathlib.Path(__file__).resolve().parents[1]
    validate_platform_identity(
        platform_root=platform_root,
        repository=arguments.platform_repository,
        sha=arguments.platform_sha,
        workflow_ref=arguments.platform_ref,
        workflow_file_path=arguments.platform_file_path,
    )
    validate_consumer(
        arguments.root,
        head_sha=arguments.head_sha,
        base_sha=arguments.base_sha,
        platform_root=platform_root,
    )


if __name__ == "__main__":
    main()
