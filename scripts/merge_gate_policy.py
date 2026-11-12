"""Pure, fail-closed policy model for the immutable merge-gate v1 workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any, BinaryIO

PROFILES = {"baseline", "python", "node", "powershell", "critical-ml"}
PROFILE_WORKFLOWS = {
    "baseline": ".github/workflows/merge-gate-v1.yml",
    "python": ".github/workflows/merge-gate-python-v1.yml",
    "node": ".github/workflows/merge-gate-node-v1.yml",
    "powershell": ".github/workflows/merge-gate-powershell-v1.yml",
    "critical-ml": ".github/workflows/merge-gate-critical-ml-v1.yml",
}
PROVIDER_STATES = {"success", "failure", "pending", "timeout", "missing", "rate-limited"}
SHA = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_REPOSITORY = "koios-ai/ci-platform"
MAX_CHANGED_PATHS = 5_000
MAX_DIFF_BYTES = 2_000_000
MAX_GIT_DIAGNOSTIC_BYTES = 8_192
DEPENDABOT_USER = {
    "login": "dependabot[bot]",
    "id": 49699333,
    "node_id": "MDM6Qm90NDk2OTkzMzM=",
    "type": "Bot",
}
DEPENDENCY_FILE = re.compile(
    r"^(?:"
    r"\.github/dependabot\.ya?ml|"
    r"package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|"
    r"pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(?:\.lock)?|pdm\.lock|"
    r"(?:requirements|constraints)(?:[-_.][A-Za-z0-9_.-]+)?\.txt|"
    r"(?:requirements|constraints)/[A-Za-z0-9_./-]+\.txt|"
    r"powershell\.lock\.json"
    r")$"
)


def execution_lanes(profile: str) -> dict[str, bool | str]:
    """Return explicit required/N/A lane policy for one immutable profile."""
    if profile not in PROFILES:
        raise ValueError("unsupported profile")
    native = profile in {"node", "powershell"}
    python_profile = profile in {"python", "critical-ml"}
    security_extension_required = python_profile or profile == "node"
    coverage_required = python_profile
    security_reason = ""
    coverage_reason = ""
    if profile == "baseline":
        security_reason = "baseline performs data-structure validation and has no executable dependency lane"
        coverage_reason = "baseline has no executable source coverage surface"
    elif profile == "powershell":
        security_reason = "no centrally owned PowerShell dependency scanner is policy-approved in v1"
        coverage_reason = "no centrally owned PowerShell coverage policy is policy-approved in v1"
    elif profile == "node":
        coverage_reason = "no centrally owned Node coverage policy is policy-approved in v1"
    return {
        "native": native,
        "python_dependencies": python_profile,
        "python_tests": python_profile,
        "bandit": python_profile,
        "python_coverage": python_profile,
        "deterministic_status": "required",
        "security_status": "required",
        "security_extension_status": "required" if security_extension_required else "not-applicable",
        "coverage_status": "required" if coverage_required else "not-applicable",
        "security_reason": security_reason,
        "coverage_reason": coverage_reason,
    }


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} is malformed")
    return value


def _workflow_provenance(context: dict[str, Any], profile: str) -> None:
    sha = context.get("workflow_sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("workflow SHA is malformed")
    expected_path = PROFILE_WORKFLOWS[profile]
    if (
        context.get("workflow_repository") != WORKFLOW_REPOSITORY
        or context.get("workflow_file_path") != expected_path
        or context.get("workflow_ref") != f"{WORKFLOW_REPOSITORY}/{expected_path}@{sha}"
    ):
        raise ValueError("workflow provenance is not immutable or does not match profile")


def _is_dependabot(pull_request: dict[str, Any]) -> bool:
    user = pull_request.get("user")
    return isinstance(user, dict) and all(user.get(field) == value for field, value in DEPENDABOT_USER.items())


def _dependabot_scope(
    head_sha: str,
    head: dict[str, Any],
    repository: dict[str, Any],
    changed_files: Any,
) -> str | None:
    head_repository = head.get("repo")
    if (
        not isinstance(head_repository, dict)
        or head_repository.get("id") != repository.get("id")
        or head_repository.get("full_name") != repository.get("full_name")
    ):
        return None
    if (
        not isinstance(changed_files, list)
        or not changed_files
        or any(not isinstance(path, str) or not path or "\\" in path for path in changed_files)
    ):
        return None
    normalized = sorted(set(changed_files))
    if len(normalized) != len(changed_files) or any(not DEPENDENCY_FILE.fullmatch(path) for path in normalized):
        return None
    payload = json.dumps(
        {
            "repository_id": repository["id"],
            "repository": repository["full_name"],
            "head_sha": head_sha,
            "changed_files": normalized,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def evaluate(context: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one GitHub event without network calls, secrets, or mutable state."""
    profile = context.get("default_profile")
    requested_profile = context.get("requested_profile", profile)
    if profile not in PROFILES or requested_profile != profile:
        raise ValueError("profile selection is not source-owned")
    profile = str(profile)
    _workflow_provenance(context, profile)

    event_name = context.get("event_name")
    if event_name not in {"pull_request", "merge_group"}:
        raise ValueError("unsupported merge-gate event")
    event = _mapping(context.get("event"), "event")
    repository = _mapping(event.get("repository"), "repository")
    repository_id = repository.get("id")
    if not isinstance(repository_id, int) or repository_id <= 0:
        raise ValueError("repository id is malformed")

    lanes = execution_lanes(profile)
    result: dict[str, Any] = {
        "profile": profile,
        "admitted": False,
        "provider_results": {},
        "dependabot_scope_digest": "",
        **lanes,
    }

    if event_name == "merge_group":
        merge_group = _mapping(event.get("merge_group"), "merge_group")
        head_sha = merge_group.get("head_sha")
        base_sha = merge_group.get("base_sha")
        if not isinstance(head_sha, str) or not SHA.fullmatch(head_sha):
            raise ValueError("merge-group head SHA is malformed")
        if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
            raise ValueError("merge-group base SHA is malformed")
        result.update(
            {
                "head_sha": head_sha,
                "base_sha": base_sha,
                "concurrency_group": f"merge-gate-v1-{profile}-{repository_id}-merge-{head_sha}",
                "blocker": "merge-group-ai-mapping-canary",
            }
        )
        return result

    pull_request = _mapping(event.get("pull_request"), "pull request")
    head = _mapping(pull_request.get("head"), "pull-request head")
    base = _mapping(pull_request.get("base"), "pull-request base")
    head_sha = head.get("sha")
    base_sha = base.get("sha")
    number = pull_request.get("number")
    if not isinstance(head_sha, str) or not SHA.fullmatch(head_sha):
        raise ValueError("pull-request head SHA is malformed")
    if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
        raise ValueError("pull-request base SHA is malformed")
    if not isinstance(number, int) or number <= 0:
        raise ValueError("pull-request number is malformed")
    head_repository = _mapping(head.get("repo"), "pull-request head repository")
    if head_repository.get("id") != repository.get("id") or head_repository.get("full_name") != repository.get(
        "full_name"
    ):
        raise ValueError("fork pull requests are explicitly unsupported by merge-gate v1")
    result.update(
        {
            "head_sha": head_sha,
            "base_sha": base_sha,
            "concurrency_group": f"merge-gate-v1-{profile}-{repository_id}-pr-{number}",
        }
    )
    if pull_request.get("draft") is True or event.get("action") == "ready_for_review":
        result["blocker"] = "draft-to-ready-hosted-rerun-canary"
        return result

    if _is_dependabot(pull_request):
        digest = _dependabot_scope(head_sha, head, repository, context.get("changed_files"))
        if digest is None:
            result["blocker"] = "dependabot-identity-or-scope-unverified"
            return result
        result["dependabot_scope_digest"] = digest
        result["blocker"] = "dependabot-no-secret-finalization"
        return result

    final_candidate = context.get("final_candidate")
    if (
        not isinstance(final_candidate, dict)
        or final_candidate.get("admitted") is not True
        or final_candidate.get("head_sha") != head_sha
    ):
        result["blocker"] = "exact-head-finalizer-not-yet-hosted"
        return result
    providers = context.get("providers")
    if not isinstance(providers, dict) or set(providers) != {"coderabbit", "codex"}:
        result["blocker"] = "provider-native-exact-head-canaries"
        return result
    for provider in ("coderabbit", "codex"):
        state = providers.get(provider)
        if state not in PROVIDER_STATES:
            raise ValueError(f"provider {provider} state is malformed")
        if state != "success":
            result["blocker"] = f"provider-{provider}-{state}"
            return result
    result["provider_results"] = dict(providers)
    result["admitted"] = True
    result["blocker"] = ""
    return result


def _bounded_git(
    command: list[str], *, cwd: Path, timeout: float, stdout_limit: int
) -> subprocess.CompletedProcess[bytes]:
    """Drain both pipes concurrently, with hard read limits and one deadline."""
    deadline = time.monotonic() + timeout
    started_readers: set[str] = set()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=sys.platform != "win32",
    )
    try:
        assert process.stdout is not None and process.stderr is not None
        results: Queue[tuple[str, bytes | OSError]] = Queue()

        def drain(stream: BinaryIO, name: str, limit: int) -> None:
            try:
                with stream:
                    payload = stream.read(limit + 1)
            except OSError as error:
                results.put((name, error))
            else:
                results.put((name, payload))

        limits = {"stdout": stdout_limit, "stderr": MAX_GIT_DIAGNOSTIC_BYTES}
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            threading.Thread(target=drain, args=(stream, name, limits[name]), daemon=True).start()
            started_readers.add(name)

        captured: dict[str, bytes] = {}
        for _ in limits:
            try:
                name, output = results.get(timeout=max(0, deadline - time.monotonic()))
            except Empty as error:
                raise subprocess.TimeoutExpired(command, timeout) from error
            if isinstance(output, OSError):
                raise ValueError("Git output could not be read") from output
            if len(output) > limits[name]:
                raise ValueError(f"Git {name} output exceeds the byte limit")
            captured[name] = output
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, code, captured["stdout"], captured["stderr"])
    finally:
        try:
            if process.returncode is None:
                try:
                    if sys.platform == "win32":
                        if process.poll() is None:
                            process.kill()
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
        finally:
            # Started readers own their pipes. Closing those pipes here can block.
            for name, unowned_pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                if unowned_pipe is not None and name not in started_readers:
                    unowned_pipe.close()


def _changed_files(target_root: Path, event_name: str, event: dict[str, Any]) -> list[str]:
    if event_name != "pull_request":
        return []
    pull_request = _mapping(event.get("pull_request"), "pull request")
    base = _mapping(pull_request.get("base"), "pull-request base").get("sha")
    head = _mapping(pull_request.get("head"), "pull-request head").get("sha")
    if not isinstance(base, str) or not SHA.fullmatch(base) or not isinstance(head, str) or not SHA.fullmatch(head):
        raise ValueError("pull-request diff SHAs are malformed")
    return git_changed_files(target_root, base, head)


def git_changed_files(target_root: Path, base: str, head: str) -> list[str]:
    """Derive the canonical path set from the exact commits and their unique merge base."""
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("pull-request diff SHAs are malformed")
    git = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false"]
    merge_bases = _bounded_git(
        [*git, "merge-base", "--all", base, head],
        cwd=target_root,
        timeout=20,
        stdout_limit=MAX_GIT_DIAGNOSTIC_BYTES,
    )
    if merge_bases.returncode or merge_bases.stderr or not re.fullmatch(rb"[0-9a-f]{40}\r?\n", merge_bases.stdout):
        raise ValueError("pull-request diff requires a unique merge base")
    merge_base = merge_bases.stdout.decode("ascii").strip()
    completed = _bounded_git(
        [
            *git,
            "-c",
            "diff.renameLimit=5000",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-status",
            "-z",
            "--find-renames=50%",
            "--find-copies=50%",
            "--find-copies-harder",
            "--diff-filter=ACDMRTUXB",
            merge_base,
            head,
            "--",
        ],
        cwd=target_root,
        timeout=40,
        stdout_limit=MAX_DIFF_BYTES,
    )
    completed.check_returncode()
    if completed.stderr:
        raise ValueError("Git did not produce a complete pull-request diff")
    fields = completed.stdout.split(b"\0")
    if not fields or fields[-1] != b"":
        raise ValueError("pull-request diff output is malformed")
    fields.pop()
    seen: set[str] = set()
    index = 0
    while index < len(fields):
        try:
            status = fields[index].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("pull-request diff status is malformed") from error
        index += 1
        if not re.fullmatch(r"[ACDMRTUXB](?:[0-9]{1,3})?", status):
            raise ValueError("pull-request diff status is malformed")
        path_count = 2 if status[0] in {"C", "R"} else 1
        if index + path_count > len(fields):
            raise ValueError("pull-request diff paths are malformed")
        for raw_path in fields[index : index + path_count]:
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("pull-request diff path is not UTF-8") from error
            if any(component in {"", ".", ".."} for component in path.split("/")) or any(
                character in path for character in "\\\r\n"
            ):
                raise ValueError("pull-request diff path is unsafe")
            seen.add(path)
            if len(seen) > MAX_CHANGED_PATHS:
                raise ValueError("pull-request diff has too many changed paths")
        index += path_count
    return sorted(seen)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-path", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-file-path", required=True)
    parser.add_argument("--default-profile", required=True)
    parser.add_argument("--target-root", type=Path)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    event = json.loads(args.event_path.read_text(encoding="utf-8"))
    context = {
        "event_name": args.event_name,
        "event": event,
        "workflow_repository": args.workflow_repository,
        "workflow_sha": args.workflow_sha,
        "workflow_ref": args.workflow_ref,
        "workflow_file_path": args.workflow_file_path,
        "default_profile": args.default_profile,
    }
    if args.target_root is not None:
        context["changed_files"] = _changed_files(args.target_root, args.event_name, event)
    result = evaluate(context)
    keys = (
        "head_sha",
        "base_sha",
        "profile",
        "concurrency_group",
        "admitted",
        "blocker",
        "native",
        "deterministic_status",
        "security_status",
        "security_extension_status",
        "coverage_status",
        "security_reason",
        "coverage_reason",
        "dependabot_scope_digest",
    )
    with args.github_output.open("a", encoding="utf-8", newline="\n") as output:
        for key in keys:
            value = result[key]
            if isinstance(value, bool):
                value = str(value).lower()
            output.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
