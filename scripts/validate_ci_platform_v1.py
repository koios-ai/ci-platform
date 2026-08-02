"""Fail-closed local validation for the immutable merge-gate v1 artifacts."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml
from generate_merge_gate_profiles import (
    PROFILE_WORKFLOW_NAMES,
    PROFILE_WORKFLOWS,
    SOURCE_JOB_GUARD,
    SOURCE_REPOSITORY,
    generated_workflows,
)
from run_quality_canaries import PRODUCTION_STATIC_POLICY
from run_quality_canaries import run as run_quality_canaries
from secret_scan import scan as scan_secrets

PROFILES = {"baseline", "python", "node", "powershell", "critical-ml"}
QUALITY_CLASSES = {
    "wrong-arguments",
    "multiple-definition",
    "identical-expression-comparison",
    "undefined-export",
    "unreachable-statements",
    "calls-to-non-callables",
    "exit-quit",
    "conflicting-attributes",
    "implicit-list-string-concatenation",
}
REQUIRED_JOBS = {
    "fast-scope",
    "fast-deterministic",
    "final-candidate",
    "deterministic",
    "security",
    "runtime-evidence",
    "coverage",
    "coderabbit-evidence",
    "codex-evidence",
    "findings-resolved",
    "merge",
}
PUBLIC_PRERELEASE_MANIFEST = "contract/public-prerelease-v1.json"
PUBLICATION_TRANSIENT_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}
PUBLICATION_FORBIDDEN_PATH_PREFIXES = (".superpowers/", "docs/superpowers/")
PUBLICATION_FORBIDDEN_TEXT_HEX = (
    "686f7273655f726163696e67",
    "686f7273652d726163696e67",
    "686f72736520726163696e67",
    "7367726569",
    "6772656974736368",
)
PUBLICATION_GIT_REGULAR_MODES = {"100644", "100755"}
PUBLICATION_REPARSE_FLAG = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
PUBLICATION_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PUBLICATION_ALLOWED_NON_PERSONAL_ADDRESSES = {"git@github.com", "user@github.com"}


SHA = re.compile(r"^[0-9a-f]{40}$")
JOB_ENV_UNAVAILABLE_DEREFERENCE = re.compile(
    r"(?<![\w.])(?:job|runner)\b",
    re.IGNORECASE,
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
DEEPSOURCE_APP = {"id": 16372, "slug": "deepsource-io"}
DEEPSOURCE_EXPECTED_CHECKS = [
    "DeepSource analysis",
    "DeepSource: Secrets",
    "DeepSource: requirements.txt",
    "DeepSource: requirements-core-next.txt",
    "DeepSource: requirements-compat-ag.txt",
    "DeepSource: requirements-maintenance.txt",
]
DEEPSOURCE_DISABLED_CHECKS = ["DeepSource: AI Review", "DeepSource: Test coverage"]
DEEPSOURCE_SCA_CAPABILITIES = {"reachability", "dynamic-risk", "epss", "cvss", "license-compliance"}
DEEPSOURCE_SIGNAL_CHECKS = {
    "python-static-quality": ["DeepSource analysis"],
    "ruff-transformer": ["DeepSource analysis"],
    "sca": [
        "DeepSource: requirements.txt",
        "DeepSource: requirements-core-next.txt",
        "DeepSource: requirements-compat-ag.txt",
        "DeepSource: requirements-maintenance.txt",
    ],
    "secrets": ["DeepSource: Secrets"],
    "docker-compose-config": ["DeepSource analysis"],
    "adapter-integrity": DEEPSOURCE_EXPECTED_CHECKS,
    "ai-review-readback": ["DeepSource: AI Review"],
    "coverage": ["DeepSource: Test coverage"],
}


def _github_expression_bodies(value: str) -> list[str]:
    """Return expression bodies with quoted literals masked.

    A delimiter-looking ``}}`` inside a quoted format string is content, not
    the end of the GitHub expression. Masking literals also keeps prose such as
    ``'runner.temp'`` from impersonating the unavailable runner root context.
    """
    bodies: list[str] = []
    cursor = 0
    while True:
        start = value.find("${{", cursor)
        if start < 0:
            return bodies
        index = start + 3
        masked: list[str] = []
        quote: str | None = None
        while index < len(value):
            character = value[index]
            if quote is not None:
                masked.append(" ")
                if character == quote:
                    if index + 1 < len(value) and value[index + 1] == quote:
                        masked.append(" ")
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if character in {"'", '"'}:
                quote = character
                masked.append(" ")
                index += 1
                continue
            if value.startswith("}}", index):
                bodies.append("".join(masked))
                cursor = index + 2
                break
            masked.append(character)
            index += 1
        else:
            return bodies


def job_env_uses_unavailable_context(value: str) -> bool:
    """Whether a job-level env scalar dereferences the root job/runner context."""
    return any(JOB_ENV_UNAVAILABLE_DEREFERENCE.search(body) for body in _github_expression_bodies(value))


SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _git_publication_entries(root: Path) -> list[tuple[str, str]] | None:
    tracked = subprocess.run(
        ["git", "ls-files", "--stage", "-z", "--cached"],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=60,
    )
    untracked = subprocess.run(
        ["git", "ls-files", "-z", "--others", "--exclude-standard"],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=60,
    )
    if tracked.returncode != 0 or untracked.returncode != 0:
        return None
    entries: dict[str, str] = {}
    for record in tracked.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.decode("ascii").split()
        if not separator or len(fields) != 3:
            raise ValueError("public pre-release Git index entry is malformed")
        mode, _object_id, stage = fields
        relative = raw_path.decode("utf-8")
        if stage != "0":
            raise ValueError(f"public pre-release Git index contains an unmerged entry: {relative}")
        if mode not in PUBLICATION_GIT_REGULAR_MODES:
            raise ValueError(f"public pre-release Git mode is not a regular blob: {relative} ({mode})")
        if relative in entries:
            raise ValueError(f"public pre-release Git index contains a duplicate path: {relative}")
        entries[relative] = mode
    for raw_path in untracked.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8")
        if relative in entries:
            raise ValueError(f"public pre-release Git inventory contains a duplicate path: {relative}")
        entries[relative] = ""
    return sorted(entries.items())


def _publication_files(root: Path) -> list[tuple[str, Path, str]]:
    lexical_root = root.absolute()
    try:
        resolved_root = lexical_root.resolve(strict=True)
    except OSError as error:
        raise ValueError("public pre-release publication root is unavailable") from error
    git_entries = _git_publication_entries(lexical_root)
    if git_entries is None:
        candidates = [(path.relative_to(lexical_root).as_posix(), "") for path in lexical_root.rglob("*")]
    else:
        candidates = git_entries
    files: list[tuple[str, Path, str]] = []
    for relative, git_mode in candidates:
        lexical = lexical_root / relative
        try:
            relative_path = lexical.relative_to(lexical_root)
        except ValueError as error:
            raise ValueError(f"public pre-release path escapes publication root: {relative}") from error
        canonical_relative = relative_path.as_posix()
        if canonical_relative == PUBLIC_PRERELEASE_MANIFEST or any(
            part in PUBLICATION_TRANSIENT_PARTS for part in relative_path.parts
        ):
            continue
        try:
            metadata = lexical.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValueError(f"public pre-release path is unavailable: {canonical_relative}") from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if lexical.is_symlink():
            raise ValueError(f"public pre-release path is not a regular non-symlink file: {canonical_relative}")
        if attributes & PUBLICATION_REPARSE_FLAG:
            raise ValueError(f"public pre-release path is a reparse point: {canonical_relative}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"public pre-release path is not a regular file: {canonical_relative}")
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as error:
            raise ValueError(f"public pre-release path is unavailable: {canonical_relative}") from error
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise ValueError(f"public pre-release path escapes publication root: {canonical_relative}")
        effective_mode = git_mode or ("100755" if metadata.st_mode & 0o111 else "100644")
        files.append((canonical_relative, lexical, effective_mode))
    return sorted(files)


def _publication_tree_attestation(
    root: Path,
    *,
    files: list[tuple[str, Path, str]] | None = None,
) -> tuple[int, str]:
    inventory = [
        {"mode": mode, "path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for relative, path, mode in (files if files is not None else _publication_files(root))
    ]
    return len(inventory), hashlib.sha256(canonical_json_bytes(inventory)).hexdigest()


def _contains_forbidden_publication_text(value: str) -> bool:
    lowered = value.lower().encode("utf-8")
    return any(bytes.fromhex(encoded) in lowered for encoded in PUBLICATION_FORBIDDEN_TEXT_HEX)


def validate_publication_boundary(root: Path) -> None:
    """Validate the sanitized, canary-only public pre-release boundary."""
    manifest_path = root / PUBLIC_PRERELEASE_MANIFEST
    if not manifest_path.is_file():
        raise ValueError("public pre-release manifest is missing")
    manifest = strict_json_load(manifest_path.read_bytes(), "public pre-release manifest")
    required_manifest = {
        "schema": "koios-ci/public-prerelease-v1",
        "repository": SOURCE_REPOSITORY,
        "visibility": "public",
        "support_level": "hosted-canaries-only",
        "publication_authorized": True,
        "authoritative_gates": False,
        "cutover_permitted": False,
        "consumer_pin_permitted": False,
        "ruleset_activation_permitted": False,
        "merge_freeze_release_permitted": False,
        "history_publication": "sanitized-root-snapshot-only",
        "attestation_scope": "all-publication-files-except-this-manifest",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {*required_manifest, "artifact_count", "artifact_tree_sha256"}
        or any(manifest.get(key) != value for key, value in required_manifest.items())
        or type(manifest.get("artifact_count")) is not int
        or manifest["artifact_count"] <= 0
        or not isinstance(manifest.get("artifact_tree_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["artifact_tree_sha256"])
    ):
        raise ValueError("public pre-release manifest policy is not closed and non-authoritative")

    contract = strict_json_load((root / "contract/v1.json").read_bytes(), "platform contract")
    expected_delivery = {
        "current_required_and_final_workflow_dependency": "cross-repository-checkout",
        "distribution": "sanitized-public-prerelease",
        "public_repository_authorized": True,
        "public_prerelease_publication_permitted": True,
        "hosted_canary_use_only": True,
        "consumer_pin_permitted": False,
        "ruleset_activation_permitted": False,
        "source_history_publication_permitted": False,
        "publication_history": "sanitized-root-snapshot-only",
        "prerelease_manifest": PUBLIC_PRERELEASE_MANIFEST,
        "pat_permitted": False,
    }
    expected_release = {
        "current_head_only": True,
        "staged_rollout_supported": False,
        "arbitrary_historical_sha_permitted": False,
        "public_prerelease_manifest": PUBLIC_PRERELEASE_MANIFEST,
        "public_prerelease_support": "hosted-canaries-only",
        "required_resolution": "protected-supported-release-manifest-with-closed-template-digests",
    }
    rollout = contract.get("x-rollout-status") if isinstance(contract, dict) else None
    if (
        contract.get("x-platform-delivery") != expected_delivery
        or contract.get("x-platform-release-policy") != expected_release
        or not isinstance(rollout, dict)
        or rollout.get("cutover_permitted") is not False
        or rollout.get("disposition") != "NOT READY"
    ):
        raise ValueError("public pre-release publication is not separated from cutover authority")
    blockers = rollout.get("blocking_requirements")
    blocker_ids = (
        {item.get("id") for item in blockers if isinstance(item, dict)} if isinstance(blockers, list) else set()
    )
    if "private-platform-delivery" in blocker_ids or "supported-release-manifest" not in blocker_ids:
        raise ValueError("public pre-release publication blockers contradict the approved delivery boundary")

    security = contract.get("x-merge-gate-v1", {}).get("common_security")
    if (
        not isinstance(security, dict)
        or security.get("tool") != "scripts/secret_scan.py"
        or security.get("config") != "contract/secret-scan-v1.json"
        or not isinstance(security.get("config_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", security["config_sha256"])
    ):
        raise ValueError("public pre-release secret policy is not bound to the common-security contract")
    publication_files = _publication_files(root)
    artifact_count, artifact_digest = _publication_tree_attestation(root, files=publication_files)
    findings = scan_secrets(
        root,
        config=root / security["config"],
        expected_config_sha256=security["config_sha256"],
        paths=[path for _, path, _ in publication_files],
    )
    if findings:
        summary = ", ".join(f"{relative}: {rule}" for relative, rule in findings)
        raise ValueError(f"public pre-release tree contains pinned secret material: {summary}")

    for relative, path, _mode in publication_files:
        lowered_path = relative.lower()
        if lowered_path.startswith(PUBLICATION_FORBIDDEN_PATH_PREFIXES):
            raise ValueError(f"public pre-release tree contains internal staging material: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"public pre-release tree contains a non-text source artifact: {relative}") from error
        if _contains_forbidden_publication_text(text):
            raise ValueError(f"public pre-release tree contains consumer-specific or personal material: {relative}")
        for address in PUBLICATION_EMAIL.findall(text):
            normalized = address.lower()
            if (
                not normalized.endswith("@example.invalid")
                and normalized not in PUBLICATION_ALLOWED_NON_PERSONAL_ADDRESSES
            ):
                raise ValueError(f"public pre-release tree contains a non-synthetic email address: {relative}")

    confirmed_count, confirmed_digest = _publication_tree_attestation(root, files=publication_files)
    if (confirmed_count, confirmed_digest) != (artifact_count, artifact_digest):
        raise ValueError("public pre-release tree changed during publication validation")
    if manifest["artifact_count"] != artifact_count or manifest["artifact_tree_sha256"] != artifact_digest:
        raise ValueError("public pre-release artifact count or digest does not match the publication tree")


def strict_json_load(payload: bytes, name: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"DeepSource parity {name} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"DeepSource parity {name} contains non-finite JSON value {value!r}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"DeepSource parity {name} is not valid JSON") from error


def verify_rsa_pkcs1v15_sha256(payload: bytes, encoded_signature: Any, public_key: dict[str, Any]) -> bool:
    if not isinstance(encoded_signature, str):
        return False
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except ValueError:
        return False
    if base64.b64encode(signature).decode("ascii") != encoded_signature:
        return False
    modulus = int(public_key["n"], 16)
    exponent = public_key["e"]
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width:
        return False
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= modulus:
        return False
    observed = pow(signature_integer, exponent, modulus).to_bytes(width, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    padding_size = width - len(digest_info) - 3
    if padding_size < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * padding_size) + b"\x00" + digest_info
    return hmac.compare_digest(observed, expected)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"workflow is not a mapping: {path}")
    mapping: dict[Any, Any] = value
    if True in mapping and "on" not in mapping:
        mapping["on"] = mapping.pop(True)
    if any(not isinstance(key, str) for key in mapping):
        raise ValueError(f"workflow has a non-string top-level key: {path}")
    return cast(dict[str, Any], mapping)


def source_job_is_suppressed(condition: Any) -> bool:
    return condition == SOURCE_JOB_GUARD or (
        isinstance(condition, str) and condition.startswith(f"{SOURCE_JOB_GUARD} && ") and "||" not in condition
    )


def workflow_event_names(events: Any) -> set[str]:
    if isinstance(events, str):
        return {events}
    if isinstance(events, list):
        return {event for event in events if isinstance(event, str)}
    if isinstance(events, dict):
        return {event for event in events if isinstance(event, str)}
    return set()


def require_owner(value: Any, where: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{where} owner is not an object")
    for key in ("owner", "command", "rule", "negative_canary"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise ValueError(f"{where} lacks a non-empty {key}")


def validate_code_quality_receipt(
    value: Any,
    *,
    name: str,
    surface: str,
    expected_state: dict[str, Any],
    as_of: dt.datetime,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "source",
        "captured_at",
        "authentication",
        "reviewer",
        "provider",
        "state",
        "sha256",
    }:
        raise ValueError(f"GitHub Code Quality {name} receipt is malformed")
    digest = value["sha256"]
    unsigned = {key: item for key, item in value.items() if key != "sha256"}
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != digest
    ):
        raise ValueError(f"GitHub Code Quality {name} receipt sha256 is invalid")
    source = value["source"]
    authentication = value["authentication"]
    reviewer = value["reviewer"]
    provider = value["provider"]
    if source != {"organization": "koios-ai", "surface": surface}:
        raise ValueError(f"GitHub Code Quality {name} receipt source is invalid")
    if (
        not isinstance(authentication, dict)
        or set(authentication) != {"authenticated", "method"}
        or authentication.get("authenticated") is not True
        or authentication.get("method") not in {"github-api", "authenticated-in-app-browser"}
    ):
        raise ValueError(f"GitHub Code Quality {name} receipt authentication is invalid")
    if (
        not isinstance(reviewer, dict)
        or set(reviewer) != {"login", "id", "type"}
        or not isinstance(reviewer.get("login"), str)
        or not reviewer["login"]
        or type(reviewer.get("id")) is not int
        or reviewer["id"] <= 0
        or reviewer.get("type") not in {"User", "App"}
    ):
        raise ValueError(f"GitHub Code Quality {name} receipt reviewer is invalid")
    if provider != {"name": "GitHub", "domain": "github.com"}:
        raise ValueError(f"GitHub Code Quality {name} receipt provider identity is invalid")
    if value["state"] != expected_state:
        raise ValueError(f"GitHub Code Quality {name} receipt state is contradictory")
    captured_at = value["captured_at"]
    if not isinstance(captured_at, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", captured_at):
        raise ValueError(f"GitHub Code Quality {name} receipt captured_at is invalid")
    captured = dt.datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    if as_of.tzinfo is None or captured > as_of or as_of - captured > dt.timedelta(days=30):
        raise ValueError(f"GitHub Code Quality {name} receipt captured_at is stale or in the future")


def validate_common_security(root: Path) -> None:
    contract = json.loads((root / "contract/v1.json").read_text(encoding="utf-8"))
    security = contract.get("x-merge-gate-v1", {}).get("common_security")
    if not isinstance(security, dict):
        raise ValueError("common secret-scan contract is absent")
    required = {
        "status": "required-all-profiles",
        "tool": "scripts/secret_scan.py",
        "tool_version": "1.0.0",
        "config": "contract/secret-scan-v1.json",
        "positive_canary": "tests/canaries/secrets/pass.txt",
        "negative_canary_parts": [
            "tests/canaries/secrets/token-prefix.txt",
            "tests/canaries/secrets/token-suffix.txt",
        ],
        "negative_exit": 2,
        "target_scope": "git-tracked-files",
        "target_code_execution": False,
    }
    if any(security.get(key) != value for key, value in required.items()):
        raise ValueError("common secret-scan ownership or canary contract is invalid")
    digest = security.get("config_sha256")
    config = root / security["config"]
    scanner = root / security["tool"]
    config_value = json.loads(config.read_text(encoding="utf-8")) if config.is_file() else None
    canonical_config = json.dumps(
        config_value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not config.is_file()
        or hashlib.sha256(canonical_config).hexdigest() != digest
        or not scanner.is_file()
    ):
        raise ValueError("common secret-scan tool/config pin is invalid")

    def run_canary(canary_root: Path, canary: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(scanner),
                "--root",
                str(canary_root),
                "--config",
                str(config),
                "--expected-config-sha256",
                digest,
                "--path",
                str(canary),
            ],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    positive = root / security["positive_canary"]
    if not positive.is_file():
        raise ValueError("common secret-scan positive canary is missing")
    result = run_canary(root, positive)
    if result.returncode != 0:
        raise ValueError(f"common secret-scan positive canary returned {result.returncode}, expected 0")

    parts = [root / relative for relative in security["negative_canary_parts"]]
    if any(not part.is_file() for part in parts):
        raise ValueError("common secret-scan composed negative canary part is missing")
    for part in parts:
        if run_canary(root, part).returncode != 0:
            raise ValueError("common secret-scan negative canary part is independently credential-shaped")
    composed = b"".join(part.read_bytes().strip() for part in parts)
    with tempfile.TemporaryDirectory(prefix="koios-secret-canary-") as temporary:
        canary_root = Path(temporary)
        negative = canary_root / "composed.txt"
        negative.write_bytes(composed)
        result = run_canary(canary_root, negative)
    if result.returncode != security["negative_exit"]:
        raise ValueError(
            f"common secret-scan negative canary returned {result.returncode}, expected {security['negative_exit']}"
        )
    if "github-token" not in result.stderr:
        raise ValueError("common secret-scan negative canary lacks the expected diagnostic")


def validate_profile_contract(root: Path, *, as_of: dt.datetime | None = None) -> None:
    as_of = as_of or dt.datetime.now(dt.UTC)
    contract = json.loads((root / "contract/v1.json").read_text(encoding="utf-8"))
    merge_gate = contract.get("x-merge-gate-v1")
    if not isinstance(merge_gate, dict):
        raise ValueError("merge-gate v1 contract is absent")
    expected_workflows = {profile: f".github/workflows/{workflow}" for profile, workflow in PROFILE_WORKFLOWS.items()}
    expected_selection = {
        "authority": "separate-organization-rulesets",
        "target_filter_template": "props.ci_profile:<profile>",
        "assignment_authority": "explicit-user-specified-only",
        "runtime_custom_property_input": False,
        "one_active_required_workflow_per_repository": True,
        "hosted_readback_required": True,
    }
    expected_source_repository_policy = {
        "repository": SOURCE_REPOSITORY,
        "profile_workflow_jobs": "source-guarded",
        "consumer_required_context": "CI / required",
        "hosted_profile_workflow_state": "disabled-in-source-repository",
        "hosted_disable_readback_required": True,
        "ruleset_concurrency_cancel_in_progress": False,
        "internal_workflow": ".github/workflows/continuous-validation.yml",
        "internal_job": "Koios CI / source validation",
        "internal_triggers": ["pull_request", "merge_group", "push-main", "schedule"],
    }
    expected_property = {
        "name": "ci_profile",
        "owner": "organization",
        "type": "single_select",
        "required": True,
        "assignment_mode": "explicit-user-specified",
        "default_value": None,
        "inheritance_permitted": False,
        "empty_value_permitted": False,
        "allowed_values": list(PROFILE_WORKFLOWS),
        "repository_actor_updates": False,
    }
    expected_rulesets = [
        {
            "name": f"Koios CI / {profile} merge gate",
            "branch_target": "~DEFAULT_BRANCH",
            "target_filter": f"props.ci_profile:{profile}",
            "required_workflow": workflow,
            "required_job": "CI / required",
        }
        for profile, workflow in expected_workflows.items()
    ]
    if (
        merge_gate.get("profile_workflows") != expected_workflows
        or merge_gate.get("profile_selection") != expected_selection
        or merge_gate.get("source_repository_policy") != expected_source_repository_policy
        or merge_gate.get("profile_property") != expected_property
        or merge_gate.get("profile_rulesets") != expected_rulesets
        or merge_gate.get("terminal_job") != {"id": "merge", "name": "CI / required"}
    ):
        raise ValueError("merge-gate profile/ruleset contract is not closed")
    expected_ci_owner = {
        "publisher": "organization-required-workflow-terminal",
        "profile_workflows": expected_workflows,
        "job": "merge",
        "required_job": "CI / required",
        "target": "event-head",
        "trusted_metadata_only": False,
    }
    if contract.get("x-context-owners", {}).get("CI / required") != expected_ci_owner:
        raise ValueError("CI / required context owner is not the active profile terminal")
    expected_coderabbit = {
        "path": ".coderabbit.yaml",
        "source": "exact-platform-template",
        "profile": "assertive",
        "label_opt_in": "ai-review-ready",
        "review_cadence": "final-only-label-opt-in",
        "automatic_review": False,
        "incremental_review": False,
        "draft_review": False,
        "autofix": False,
        "write_capable_finishing_touches": False,
        "usage_based_add_on": "disabled",
        "recurring_credit_purchases": False,
        "automatic_credit_top_up": False,
        "rate_limit_exhaustion": "fail-closed-wait-no-provider-pass",
        "organization_override_readback_required": True,
    }
    expected_codex = {
        "review_cadence": "exact-head-final-only",
        "provider_pass_requires_exact_head": True,
        "purchased_credits_enabled": False,
        "automatic_credit_reload": False,
        "usage_overage_permitted": False,
        "quota_exhaustion": "fail-closed-wait-no-provider-pass",
        "hosted_readback_required": True,
    }
    expected_deepsource = {
        "subscription": "team-fixed-30-usd-per-month-per-contributor",
        "deterministic_analysis_enabled": True,
        "sca_enabled": True,
        "fail_on_no_data_enabled": True,
        "checked_in_deepsource_toml_enabled": True,
        "master_ai_agents_enabled": False,
        "automatic_ai_credit_recharge_enabled": False,
        "ai_features_required_disabled": [
            "ai-review",
            "ai-autofix",
            "enhanced-secrets-ai",
            "pr-report-card-ai",
        ],
        "ai_review_context_permitted": False,
        "hosted_feature_readback_required": True,
        "observed_on": "2026-07-27",
    }
    expected_code_quality = {
        "state": "disabled",
        "policy": "permanent-exclusion",
        "observed_control": "Enable Code Quality",
        "context_present": False,
        "configuration_present": False,
        "canary_present": False,
        "organization_repository_access_required": "no-repositories",
        "organization_repository_access_enforcement_required": True,
        "reactivation_permitted": False,
        "replacement": "contract/deterministic-quality-v1.json",
        "observed_on": "2026-07-27",
    }
    expected_toolchain = {
        "control_plane_python": "3.12.13",
        "requirements_file": "requirements-dev.txt",
        "requirements_state": "exact-versions-without-hashes",
        "immutable_supply_chain_proven": False,
        "required_resolution": [
            "hash-locked-requirements-with-require-hashes",
            "digest-pinned-prebuilt-control-plane-image",
        ],
    }
    expected_dependabot = {
        "current_state": "blocked-no-secret-finalization",
        "paid_ai_exemption_active": False,
        "future_exemption_binding_required": {
            "pull_request_actor": "dependabot[bot]-exact-app-identity",
            "event_sender": "dependabot[bot]-exact-app-identity",
            "event_name": "pull_request",
            "repository": "same-repository-id-and-full-name",
            "pull_request_number": "exact-current-pull-request",
            "head_sha": "exact-current-head",
            "base_sha": "exact-current-base",
            "changed_paths": "dependency-only-full-copy-rename-delete-proof",
        },
        "synthetic_provider_pass_permitted": False,
    }
    code_quality = contract.get("x-github-code-quality-policy")
    code_quality_static = (
        {
            key: value
            for key, value in code_quality.items()
            if key not in {"organization_repository_access_receipt", "billing_cessation_receipt"}
        }
        if isinstance(code_quality, dict)
        else None
    )
    if (
        contract.get("x-coderabbit-policy") != expected_coderabbit
        or contract.get("x-codex-policy") != expected_codex
        or contract.get("x-deepsource-policy") != expected_deepsource
        or code_quality_static != expected_code_quality
        or not isinstance(code_quality, dict)
        or set(code_quality)
        != {
            *expected_code_quality,
            "organization_repository_access_receipt",
            "billing_cessation_receipt",
        }
        or contract.get("x-platform-toolchain-integrity") != expected_toolchain
        or contract.get("x-dependabot-policy") != expected_dependabot
    ):
        raise ValueError("provider cost controls or Dependabot future-exemption bindings are not closed")
    expected_invalidation = {
        "implementation_status": "implemented-hosted-unverified",
        "design_template": "templates/consumer/.github/workflows/invalidate-final-labels.yml",
        "planned_consumer_path": ".github/workflows/invalidate-final-labels.yml",
        "platform_canary_workflow": ".github/workflows/invalidate-final-labels.yml",
        "required_source": "trusted-default-branch",
        "hosted_readback_required": True,
        "events": [
            "pull_request_target:synchronize",
            "pull_request_target:reopened",
            "pull_request_target:converted_to_draft",
        ],
        "labels": ["ai-review-ready", "ci-final"],
        "labels_only": True,
        "required_check_contexts_invalidated": False,
        "same_sha_lifecycle_transitions_blocked_until_external_enforcement": [
            "closed-to-reopened",
            "draft-to-ready",
        ],
    }
    if contract.get("x-sha-invalidation-controller") != expected_invalidation:
        raise ValueError("SHA/label invalidation controller is not implemented but hosted-unverified and fail-closed")
    expected_finalizer = {
        "implementation_status": "local-complete-hosted-unverified",
        "subject_template": "templates/consumer/.github/workflows/final-subject-v1.yml",
        "controller_template": "templates/consumer/.github/workflows/finalize-python-v1.yml",
        "resume_template": "templates/consumer/.github/workflows/resume-finalizer-v1.yml",
        "dispatch_action": ".github/actions/dispatch-finalizer",
        "subject_run_name": "koios-final-subject-v1",
        "controller_run_name": "koios-finalizer-v1",
        "source_attestation_schema": "koios-run-source-v3",
        "source_commit_binding": "controller-and-subject-head-sha-equal-pr-base-sha",
        "complete_review_thread_pagination": True,
        "complete_same_head_attempt_inventory": True,
        "gate_job_names": {
            "deterministic": "Platform / deterministic final evidence",
            "security": "Platform / security evidence",
            "coverage": "Platform / coverage evidence verification",
        },
        "github_caller_job_prefix_permitted": True,
        "cross_run_singleflight": "github-actions-concurrency-repository-pr-head",
        "cancel_in_progress": False,
        "broad_rerun_endpoint_permitted": False,
        "resume_mode": "automatic-workflow-run-completed-bound-to-exact-subject-run-and-attempt",
        "hosted_readback_flags_default_false": True,
        "codex_hosted_canary_default": "disabled",
        "codex_native_result": "exact-current-review-body-PASS",
        "cutover_permitted": False,
    }
    if contract.get("x-exact-head-finalizer") != expected_finalizer:
        raise ValueError("exact-head finalizer contract is not local-complete, hosted-unverified, and fail-closed")
    expected_native_provider_evidence = {
        "provider": "DeepSource",
        "activation": "trusted-base-.deepsource.toml",
        "target": "exact-pull-request-head",
        "required_configured_dependency_contexts": True,
        "retained_signal_policy": "defense-in-depth-until-central-parity-proven",
        "retained_sca_signals": [
            "reachability",
            "dynamic-risk",
            "epss",
            "cvss",
            "license-compliance",
        ],
        "ai_review_desired_state": "disabled",
        "ai_review_disabled_readback_required": True,
        "ai_review_context_permitted": False,
        "observed_ai_review_context_policy": "fail-closed-hosted-drift",
        "ignore_disabled_test_coverage": True,
        "fail_on_no_data_required": True,
        "checked_in_configuration_required": True,
        "local_wrapper_removal_gate": "hosted-exact-head-canary",
    }
    native_provider_evidence = (
        contract.get("x-context-owners", {}).get("Security / required", {}).get("native_provider_evidence")
    )
    if native_provider_evidence != expected_native_provider_evidence:
        raise ValueError("DeepSource AI Review owner policy is not disabled and fail-closed on hosted drift")
    blockers = merge_gate.get("release_blockers")
    deepsource_blocker = "deepsource-retain-or-replace-dispositions-and-ai-review-disabled-readback"
    code_quality_blockers = {
        "github-code-quality-org-no-repositories-enforced-readback",
        "github-code-quality-billing-cessation-readback",
    }
    code_quality_receipts = (
        code_quality.get("organization_repository_access_receipt"),
        code_quality.get("billing_cessation_receipt"),
    )
    if all(receipt is None for receipt in code_quality_receipts):
        required_code_quality_blockers = code_quality_blockers
    elif all(isinstance(receipt, dict) for receipt in code_quality_receipts):
        validate_code_quality_receipt(
            code_quality_receipts[0],
            name="organization repository access",
            surface="organization-code-quality-repository-access",
            expected_state={"repository_access": "no-repositories", "enforced": True},
            as_of=as_of,
        )
        validate_code_quality_receipt(
            code_quality_receipts[1],
            name="billing cessation",
            surface="organization-code-quality-billing",
            expected_state={"billing_state": "ceased", "future_charges": False},
            as_of=as_of,
        )
        required_code_quality_blockers = set()
    else:
        raise ValueError("GitHub Code Quality receipts are incomplete")
    required_blockers = {
        "platform-source-profile-workflows-disabled-readback",
        "profile-ruleset-hosted-readback",
        "untrusted-runtime-evidence-hosted-canary",
        "runtime-output-bounded-supervisor-hosted-canary",
        "protected-affected-test-supervisor-canary",
        "mypy-adoption-ratchet-hosted-canary",
        "first-critical-consumer-test-policy-v1-migration",
        "first-critical-consumer-python-manifest-v1-migration",
        "coderabbit-cost-controls-hosted-readback",
        "codex-cost-controls-hosted-readback",
        "deepsource-ai-cost-controls-hosted-readback",
        "trusted-same-run-source-attestation-adapter-wiring",
        "complete-graphql-equivalent-review-thread-resolution-readback",
        "immutable-workflow-promoter-identities",
        "exact-label-invalidation-same-sha-lifecycle-controller",
        "complete-same-pr-head-run-inventory-no-newer-failure",
        "github-native-transactional-single-flight-across-hosted-runners",
        "node-corepack-manager-artifact-digests",
        "powershell-pester-artifact-digest",
        "hash-locked-platform-toolchain-or-digest-pinned-image",
    }
    if (
        merge_gate.get("release_status") != "NOT READY"
        or not isinstance(blockers, list)
        or not (required_blockers | required_code_quality_blockers) <= set(blockers)
        or bool(code_quality_blockers & set(blockers)) != bool(required_code_quality_blockers)
    ):
        raise ValueError("merge-gate release blockers omit required hosted or consumer migration proof")
    if deepsource_blocker not in blockers or any(
        isinstance(blocker, str) and "deepsource" in blocker.lower() and "retir" in blocker.lower()
        for blocker in blockers
    ):
        raise ValueError(
            "DeepSource release remains blocked on retain-or-replace dispositions and AI Review disabled readback"
        )


def validate_workflow(root: Path) -> None:
    if not (root / "scripts/merge_gate_policy.py").is_file() or not (root / "scripts/profile_runner.py").is_file():
        raise ValueError("authoritative merge-gate scripts are missing")
    for profile, filename in PROFILE_WORKFLOWS.items():
        path = root / ".github" / "workflows" / filename
        workflow = load_yaml(path)
        events = workflow.get("on")
        if workflow.get("name") != PROFILE_WORKFLOW_NAMES[profile]:
            raise ValueError("merge gate has an unstable profile-qualified workflow name")
        if events != {"pull_request": None, "merge_group": None}:
            raise ValueError("source-bound merge gate must use only unfiltered pull_request and merge_group")
        if workflow.get("permissions") != {"contents": "read"}:
            raise ValueError("merge gate default permissions must be read-only")
        if workflow.get("env") != {"CI_PLATFORM_PROFILE": profile}:
            raise ValueError("merge gate profile does not match its immutable source path")
        if f"merge-gate-v1-{profile}-" not in str(workflow.get("concurrency", {}).get("group", "")):
            raise ValueError("merge gate concurrency is not profile-scoped")
        if "cancel-in-progress" in workflow.get("concurrency", {}):
            raise ValueError("ruleset workflow must not configure cancel-in-progress")
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict) or set(jobs) != REQUIRED_JOBS:
            raise ValueError("merge gate job topology is not closed")
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                raise ValueError("merge gate has malformed job")
            if not source_job_is_suppressed(job.get("if")):
                raise ValueError(f"merge gate job {job_id} lacks the fail-closed source repository guard")
        setup_python_steps = [
            step
            for job in jobs.values()
            if isinstance(job, dict)
            for step in job.get("steps", [])
            if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/setup-python@")
        ]
        if not setup_python_steps or any(
            step.get("with", {}).get("python-version") != "3.12.13" for step in setup_python_steps
        ):
            raise ValueError("merge gate control-plane Python patch version is not immutable")
        selected_profile = jobs["fast-scope"].get("outputs", {}).get("profile")
        if "strategy" in jobs["deterministic"] or selected_profile != "${{ steps.scope.outputs.profile }}":
            raise ValueError("merge gate must select one source-owned profile")
        policy_steps = [
            step
            for step in jobs["fast-scope"].get("steps", [])
            if isinstance(step, dict) and "merge_gate_policy.py" in str(step.get("run", ""))
        ]
        if len(policy_steps) != 1:
            raise ValueError("merge gate does not execute the authoritative policy model")
        fast_job = jobs["fast-deterministic"]
        fast_raw = json.dumps(fast_job, sort_keys=True)
        fast_step_names = [step.get("name") for step in fast_job.get("steps", []) if isinstance(step, dict)]
        expected_fast_step_names = [
            "Check out immutable platform source",
            "Check out exact untrusted target",
            "Set up pinned Python",
            "Install pinned platform-only fast tools",
            "Run bounded format lint and protected manifest validation",
            "Scan all tracked bytes for secrets",
            "Fail closed pending protected affected-test supervisor canary",
        ]
        forbidden_fast_commands = (
            "run_isolated_runtime.py",
            "run_test_policy.py",
            "python -m bandit",
            "pip-audit",
            "target/requirements",
            "node_modules",
            "python -m pytest",
            "invoke-pester",
        )
        if (
            fast_job.get("needs") != "fast-scope"
            or fast_job.get("if") != f"{SOURCE_JOB_GUARD} && needs.fast-scope.result == 'success'"
            or "final-candidate" in fast_raw
            or "profile_runner.py --execute" not in fast_raw
            or "--lane deterministic" not in fast_raw
            or "secret_scan.py" not in fast_raw
            or "platform/requirements-dev.txt" not in fast_raw
            or "pending protected affected-test supervisor canary" not in fast_raw
            or fast_step_names != expected_fast_step_names
            or any(command in fast_raw.lower() for command in forbidden_fast_commands)
        ):
            raise ValueError("always-on fast deterministic lane is not fail-closed and scope-bound")
        for job_id in ("deterministic", "security", "runtime-evidence", "coverage"):
            job = jobs[job_id]
            if (
                "final-candidate" not in job.get("needs", [])
                or "needs.final-candidate.result == 'success'" not in str(job.get("if", ""))
                or "needs.final-candidate.outputs.admitted == 'true'" not in str(job.get("if", ""))
            ):
                raise ValueError("heavy profile execution is not final-candidate gated")
            steps = job.get("steps", [])
            platform_steps = [
                step for step in steps if isinstance(step, dict) and step.get("with", {}).get("path") == "platform"
            ]
            if len(platform_steps) != 1 or platform_steps[0].get("with") != {
                "repository": "${{ job.workflow_repository }}",
                "ref": "${{ job.workflow_sha }}",
                "path": "platform",
                "persist-credentials": False,
            }:
                raise ValueError("immutable platform source checkout is not bound to job.workflow_sha")
            target_steps = [
                step for step in steps if isinstance(step, dict) and step.get("with", {}).get("path") == "target"
            ]
            if len(target_steps) != 1 or target_steps[0].get("with") != {
                "ref": "${{ needs.fast-scope.outputs.head_sha }}",
                "fetch-depth": 0,
                "path": "target",
                "persist-credentials": False,
            }:
                raise ValueError("profile execution target is not bound to the exact event head")
        runner_steps = [
            step
            for step in jobs["deterministic"].get("steps", [])
            if isinstance(step, dict) and step.get("name") == "Run deterministic profile"
        ]
        if (
            len(runner_steps) != 1
            or "profile_runner.py --execute" not in str(runner_steps[0].get("run", ""))
            or "--lane deterministic" not in str(runner_steps[0].get("run", ""))
        ):
            raise ValueError("profile execution is not authoritatively wired")
        security_steps = jobs["security"].get("steps", [])
        required_security = [
            step
            for step in security_steps
            if isinstance(step, dict) and step.get("name") == "Run required security profile"
        ]
        not_applicable_security = [
            step
            for step in security_steps
            if isinstance(step, dict) and step.get("name") == "Record explicit security not-applicable"
        ]
        if (
            len(required_security) != 1
            or "--lane security" not in str(required_security[0].get("run", ""))
            or len(not_applicable_security) != 1
            or "not-applicable" not in str(not_applicable_security[0].get("run", ""))
        ):
            raise ValueError("merge gate security applicability handling is incomplete")
        runtime_raw = json.dumps(jobs["runtime-evidence"], sort_keys=True)
        coverage_raw = json.dumps(jobs["coverage"], sort_keys=True)
        if (
            "run_isolated_runtime.py" not in runtime_raw
            or "upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" not in runtime_raw
            or "/var/run/docker.sock" in runtime_raw
            or "verify_runtime_evidence.py" not in coverage_raw
            or "download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" not in coverage_raw
            or "pending unforgeable target-supervisor hosted canary" not in coverage_raw
        ):
            raise ValueError("isolated runtime evidence is not fresh-verified and fail-closed")
        terminal = jobs["merge"]
        if terminal.get("name") != "CI / required" or terminal.get("if") != f"{SOURCE_JOB_GUARD} && always()":
            raise ValueError("merge gate has no stable fail-closed terminal job")
        terminal_needs = terminal.get("needs", [])
        if set(terminal_needs) != REQUIRED_JOBS - {"merge"}:
            raise ValueError("terminal gate does not consume every admission lane")
        terminal_steps = terminal.get("steps", [])
        expected_terminal_assertions = {
            f"test '${{{{ needs.{job_id}.result }}}}' = success" for job_id in terminal_needs
        }
        expected_terminal_assertions.add("test '${{ needs.final-candidate.outputs.admitted }}' = true")
        if (
            len(terminal_steps) != 1
            or not isinstance(terminal_steps[0], dict)
            or terminal_steps[0].get("name") != "Enforce one stable fail-closed admission result"
            or terminal_steps[0].get("shell") != "bash"
            or {line.strip() for line in str(terminal_steps[0].get("run", "")).splitlines() if line.strip()}
            != expected_terminal_assertions
        ):
            raise ValueError("terminal gate aggregation does not reject every non-success result and admitted=false")
        raw = path.read_text(encoding="utf-8").lower()
        forbidden_capabilities = (
            "secrets.",
            "github.token",
            "statuses: write",
            "checks: write",
            "pull_request_target",
            "workflow_dispatch",
            "props.ci_profile",
        )
        for forbidden in forbidden_capabilities:
            if forbidden in raw:
                raise ValueError(f"untrusted merge gate contains forbidden capability: {forbidden}")
        for job in jobs.values():
            if not isinstance(job, dict):
                raise ValueError("merge gate has malformed job")
            permissions = job.get("permissions")
            if not isinstance(permissions, dict) or any(
                value not in {"read", "none"} for value in permissions.values()
            ):
                raise ValueError("untrusted merge gate job has non-read permission")
            for step in job.get("steps", []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                reference = str(step["uses"])
                if reference.startswith("./"):
                    raise ValueError("untrusted merge gate may not use local actions")
                if "@" not in reference or not SHA.fullmatch(reference.rsplit("@", 1)[1]):
                    raise ValueError("merge gate action is not full-SHA pinned")

    generated = generated_workflows(root)
    for generated_path, expected in generated.items():
        if not generated_path.is_file() or generated_path.read_text(encoding="utf-8") != expected:
            raise ValueError(f"generated merge-gate workflow drift: {generated_path.name}")

    continuous = load_yaml(root / ".github/workflows/continuous-validation.yml")
    continuous_events = continuous.get("on")
    expected_continuous_events = {
        "pull_request": None,
        "merge_group": None,
        "push": {"branches": ["main"]},
        "schedule": [{"cron": "17 3 * * *"}],
    }
    if continuous_events != expected_continuous_events:
        raise ValueError("continuous validation must cover source pull requests, merge groups, main, and schedule")
    if continuous.get("name") in set(PROFILE_WORKFLOW_NAMES.values()):
        raise ValueError("continuous validation must not impersonate merge admission")
    continuous_jobs = continuous.get("jobs", {})
    if not isinstance(continuous_jobs, dict) or set(continuous_jobs) != {"validation"}:
        raise ValueError("continuous validation must remain the single source repository gate")
    continuous_job = continuous_jobs.get("validation", {})
    if not isinstance(continuous_job, dict) or continuous_job.get("name") != "Koios CI / source validation":
        raise ValueError("continuous validation has no stable source repository job")
    continuous_steps = continuous_job.get("steps", [])
    setup_steps = [
        step for step in continuous_steps if isinstance(step, dict) and step.get("name") == "Set up pinned Python"
    ]
    install_steps = [
        step
        for step in continuous_steps
        if isinstance(step, dict) and step.get("name") == "Install pinned validation dependencies"
    ]
    validate_steps = [
        step
        for step in continuous_steps
        if isinstance(step, dict) and step.get("name") == "Validate immutable platform contract"
    ]
    integrity_steps = [
        step
        for step in continuous_steps
        if isinstance(step, dict) and step.get("name") == "Verify validation dependency integrity"
    ]
    if (
        len(setup_steps) != 1
        or setup_steps[0].get("with", {}).get("python-version") != "3.12.13"
        or len(install_steps) != 1
        or "requirements-dev.txt" not in str(install_steps[0].get("run", ""))
        or len(integrity_steps) != 1
        or "pip check" not in str(integrity_steps[0].get("run", ""))
        or len(validate_steps) != 1
        or "--structural-only" not in str(validate_steps[0].get("run", ""))
    ):
        raise ValueError("continuous validation does not provision its pinned structural runtime")
    expected_source_commands = {
        "Reject generated workflow drift": "python scripts/generate_merge_gate_profiles.py --root . --check",
        "Validate immutable platform contract": "python scripts/validate_ci_platform_v1.py --root . --structural-only",
        "Lint platform source": "python -m ruff check . --no-cache",
        "Check platform formatting": "python -m ruff format --check . --no-cache",
        "Type-check all platform scripts": "python -m mypy scripts --ignore-missing-imports",
        "Test platform with plugins auto-loaded": (
            'python -B -m pytest tests -q -n 2 -k "not test_complete_platform_suite_runs_in_each_plugin_mode"'
        ),
        "Test platform with plugins disabled": (
            "python -B -m pytest tests -q -p xdist.plugin -n 2 "
            '-k "not test_complete_platform_suite_runs_in_each_plugin_mode"'
        ),
    }
    source_steps_by_name = {
        step.get("name"): step
        for step in continuous_steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }
    if any(
        source_steps_by_name.get(name, {}).get("run") != command for name, command in expected_source_commands.items()
    ):
        raise ValueError("continuous validation omits substantive source repository checks")
    if "env" in source_steps_by_name["Test platform with plugins auto-loaded"] or source_steps_by_name[
        "Test platform with plugins disabled"
    ].get("env") != {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}:
        raise ValueError("continuous validation pytest plugin matrix is incomplete")

    source_triggers = {"pull_request", "merge_group", "push", "schedule"}
    internal_source_workflow = "continuous-validation.yml"
    workflow_directory = root / ".github" / "workflows"
    for candidate_path in sorted((*workflow_directory.glob("*.yml"), *workflow_directory.glob("*.yaml"))):
        candidate = load_yaml(candidate_path)
        candidate_jobs = candidate.get("jobs")
        if not isinstance(candidate_jobs, dict):
            raise ValueError(f"workflow has malformed jobs: {candidate_path.name}")
        for job_id, job in candidate_jobs.items():
            if not isinstance(job, dict):
                raise ValueError(f"workflow has malformed job: {candidate_path.name}:{job_id}")
            job_env = job.get("env", {})
            if not isinstance(job_env, dict):
                raise ValueError(f"workflow job env is malformed: {candidate_path.name}:{job_id}")
            for name, value in job_env.items():
                raw = str(value)
                if job_env_uses_unavailable_context(raw):
                    raise ValueError(
                        f"workflow context is unavailable at job-level env scope: {candidate_path.name}:{job_id}:{name}"
                    )
        candidate_event_names = workflow_event_names(candidate.get("on"))
        if not source_triggers & candidate_event_names:
            continue
        if candidate_path.name == internal_source_workflow:
            continue
        if any(
            not isinstance(job, dict) or not source_job_is_suppressed(job.get("if")) for job in candidate_jobs.values()
        ):
            raise ValueError(
                "continuous validation is not the sole source repository admission-capable gate: "
                f"{candidate_path.name} has an unsuppressed source-triggered job"
            )
    legacy = load_yaml(root / ".github/workflows/required.yml")
    legacy_events = legacy.get("on")
    legacy_job = legacy.get("jobs", {}).get("required", {})
    if (
        legacy.get("name") != "LEGACY / inactive required integrity"
        or legacy_events != {"workflow_dispatch": None}
        or not isinstance(legacy_job, dict)
        or legacy_job.get("name") == "CI / required"
    ):
        raise ValueError("legacy required workflow remains a competing v1 ruleset candidate")
    reusable = load_yaml(root / ".github/workflows/reusable-final.yml")
    if reusable.get("name") != "LEGACY / inactive reusable final evidence":
        raise ValueError("legacy reusable workflow is not clearly deactivated for v1")


def validate_quality_map(root: Path) -> None:
    quality = json.loads((root / "contract/deterministic-quality-v1.json").read_text(encoding="utf-8"))
    exclusion = quality.get("github_code_quality")
    if exclusion != {
        "enabled": False,
        "policy": "permanent-exclusion",
        "contexts": [],
        "workflows": [],
        "extensions": [],
        "configurations": [],
        "canaries": [],
        "organization_repository_access_required": "no-repositories",
        "organization_repository_access_enforcement_required": True,
        "reactivation_permitted": False,
    }:
        raise ValueError("GitHub Code Quality exclusion is not permanent and empty")
    classes = quality.get("classes")
    if not isinstance(classes, dict) or set(classes) != QUALITY_CLASSES:
        raise ValueError("deterministic quality map does not cover every severe class")
    for name, entry in classes.items():
        if not isinstance(entry, dict):
            raise ValueError(f"quality class {name} is malformed")
        owner = entry.get("owner")
        if owner == "native-only":
            raise ValueError(f"quality class {name} is native-only")
        if not isinstance(owner, dict):
            raise ValueError(f"quality class {name} has no owner")
        if owner.get("tool") not in PRODUCTION_STATIC_POLICY:
            raise ValueError(f"quality class {name} has an unapproved owner")
        for key in ("package", "command", "config", "rule", "version"):
            if not isinstance(owner.get(key), str) or not owner[key].strip():
                raise ValueError(f"quality class {name} lacks enforced {key}")
        expected_package = "ruff" if owner["tool"] == "ruff" else "mypy"
        expected_policy = PRODUCTION_STATIC_POLICY[owner["tool"]]
        if (
            owner["package"] != expected_package
            or owner["command"] != expected_policy["command"]
            or owner["config"] != expected_policy["config"]
            or not re.fullmatch(r"\d+\.\d+\.\d+", owner["version"])
        ):
            raise ValueError(f"quality class {name} has an invalid executable version binding")
        for key in ("positive_canary", "negative_canary"):
            fixture = entry.get(key)
            if not isinstance(fixture, str) or not fixture.strip():
                raise ValueError(f"quality class {name} lacks {key}")
            candidate = (root / fixture).resolve()
            if root.resolve() not in candidate.parents or not candidate.is_file():
                raise ValueError(f"quality class {name} {key} is unavailable: {fixture}")
    run_quality_canaries(root, root / "contract/deterministic-quality-v1.json")


def validate_deepsource_parity(root: Path, *, as_of: dt.datetime) -> None:
    schema = strict_json_load(
        (root / "contract/deepsource-parity-v1.schema.json").read_bytes(),
        "platform schema",
    )
    if not isinstance(schema, dict):
        raise ValueError("DeepSource parity platform schema is not an object")
    signal_definition = schema.get("$defs", {}).get("signal", {})
    required_signal_ids = {
        "python-static-quality",
        "ruff-transformer",
        "sca",
        "secrets",
        "docker-compose-config",
        "adapter-integrity",
        "ai-review-readback",
        "coverage",
    }
    if (
        schema.get("properties", {}).get("schema_version", {}).get("const") != 2
        or set(signal_definition.get("properties", {}).get("id", {}).get("enum", [])) != required_signal_ids
    ):
        raise ValueError("DeepSource parity schema does not cover all material signal classes")
    expectation_contract = schema.get("x-koios-ci-canary-expectations-v1")
    if (
        not isinstance(expectation_contract, dict)
        or set(expectation_contract) != {"version", "attestation", "signals"}
        or expectation_contract.get("version") != 1
        or not isinstance(expectation_contract.get("signals"), dict)
        or set(expectation_contract["signals"]) != required_signal_ids
    ):
        raise ValueError("DeepSource platform-owned canary expectations are incomplete")
    attestation_policy = expectation_contract["attestation"]
    if not isinstance(attestation_policy, dict) or set(attestation_policy) != {
        "algorithm",
        "key_id",
        "public_key",
        "public_key_sha256",
    }:
        raise ValueError("DeepSource platform-owned attestation policy is invalid")
    public_key = attestation_policy["public_key"]
    if (
        attestation_policy["algorithm"] != "rsa-pkcs1v15-sha256"
        or attestation_policy["key_id"] != "koios-ci-deepsource-canary-2026-07"
        or not isinstance(public_key, dict)
        or set(public_key) != {"kty", "n", "e"}
        or public_key.get("kty") != "RSA"
        or public_key.get("e") != 65537
        or not isinstance(public_key.get("n"), str)
        or not re.fullmatch(r"[89a-f][0-9a-f]{511}", public_key["n"])
        or not re.fullmatch(r"[0-9a-f]{64}", str(attestation_policy["public_key_sha256"]))
        or hashlib.sha256(canonical_json_bytes(public_key)).hexdigest() != attestation_policy["public_key_sha256"]
    ):
        raise ValueError("DeepSource platform-owned attestation key binding is invalid")
    canary_expectations: dict[str, dict[str, dict[str, Any]]] = expectation_contract["signals"]
    diagnostic_digests: set[str] = set()
    output_digests: set[str] = set()
    for signal_id, signal_expectations in canary_expectations.items():
        if not isinstance(signal_expectations, dict) or set(signal_expectations) != {"positive", "negative"}:
            raise ValueError(f"DeepSource {signal_id} platform-owned canary expectations are invalid")
        for kind, expectation in signal_expectations.items():
            if (
                not isinstance(expectation, dict)
                or set(expectation)
                != {
                    "exit",
                    "stdout_sha256",
                    "stderr_sha256",
                    "diagnostic_stream",
                    "diagnostic_sha256",
                }
                or type(expectation["exit"]) is not int
                or (kind == "positive" and expectation["exit"] != 0)
                or (kind == "negative" and expectation["exit"] in {0, 126, 127})
                or expectation["diagnostic_stream"] not in {"stdout", "stderr"}
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", str(expectation[field])) or expectation[field] == EMPTY_SHA256
                    for field in ("stdout_sha256", "stderr_sha256", "diagnostic_sha256")
                )
                or expectation["diagnostic_sha256"] != expectation[f"{expectation['diagnostic_stream']}_sha256"]
            ):
                raise ValueError(f"DeepSource {signal_id}.{kind} platform-owned canary expectation is invalid")
            diagnostic_digests.add(expectation["diagnostic_sha256"])
            output_digests.update((expectation["stdout_sha256"], expectation["stderr_sha256"]))
    if len(diagnostic_digests) != len(required_signal_ids) * 2:
        raise ValueError("DeepSource platform-owned canary diagnostic expectations must be unique")
    if len(output_digests) != len(required_signal_ids) * 4:
        raise ValueError("DeepSource platform-owned canary output expectations must be unique")
    parity = strict_json_load(
        (root / "templates/consumer/.github/ci-platform-deepsource-parity.json").read_bytes(),
        "consumer map",
    )
    if not isinstance(parity, dict):
        raise ValueError("DeepSource parity consumer map is not an object")
    try:
        jsonschema.Draft202012Validator(schema).validate(parity)
    except jsonschema.ValidationError as error:
        field = ".".join(str(part) for part in error.absolute_path) or "root"
        label = ""
        path_parts = list(error.absolute_path)
        if len(path_parts) >= 2 and path_parts[0] == "signals" and isinstance(path_parts[1], int):
            invalid_signal = parity.get("signals", [])[path_parts[1]]
            if isinstance(invalid_signal, dict) and invalid_signal.get("id") == "ai-review-readback":
                label = " for AI Review"
        raise ValueError(f"DeepSource parity schema violation{label} at {field}: {error.message}") from error
    if parity.get("schema_version") != 2 or set(parity.get("profiles", [])) != PROFILES:
        raise ValueError("DeepSource parity profiles are incomplete")
    if parity.get("template_status") != "complete":
        raise ValueError("DeepSource disposition is blocked until a complete consumer parity proof exists")
    evidence_root_value = parity.get("evidence_root")
    if not isinstance(evidence_root_value, str) or not evidence_root_value:
        raise ValueError("DeepSource parity lacks evidence_root")
    evidence_root = (root / evidence_root_value).resolve()
    if root.resolve() not in evidence_root.parents or not evidence_root.is_dir():
        raise ValueError("DeepSource parity evidence_root is unsafe or unavailable")

    repository = parity.get("repository")
    source_config_sha = parity.get("source_config_sha")
    source_config_digest = parity.get("source_config_digest")
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("DeepSource parity repository is invalid")
    if not isinstance(source_config_sha, str) or not SHA.fullmatch(source_config_sha):
        raise ValueError("DeepSource parity source_config_sha is not a full SHA")
    if not isinstance(source_config_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", source_config_digest):
        raise ValueError("DeepSource parity source_config_digest is invalid")

    def parse_time(value: Any, name: str) -> dt.datetime:
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
            raise ValueError(f"DeepSource parity {name} timestamp is invalid")
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed > as_of or as_of - parsed > dt.timedelta(days=30):
            raise ValueError(f"DeepSource parity {name} timestamp is stale or in the future")
        return parsed

    def semantic_object(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"DeepSource parity {name} semantic payload is not an object")
        return value

    def require_exact_keys(value: dict[str, Any], keys: set[str], name: str) -> None:
        if set(value) != keys:
            raise ValueError(f"DeepSource parity {name} semantic fields are invalid")

    def validate_source(value: Any, name: str) -> None:
        source = semantic_object(value, f"{name}.source")
        require_exact_keys(source, {"repository", "sha"}, f"{name}.source")
        if source != {"repository": repository, "sha": source_config_sha}:
            raise ValueError(f"DeepSource parity {name} source metadata does not bind the consumer")

    def validate_reviewer(value: Any, name: str) -> None:
        reviewer = semantic_object(value, f"{name}.reviewer")
        require_exact_keys(reviewer, {"login", "id", "type"}, f"{name}.reviewer")
        if (
            not isinstance(reviewer["login"], str)
            or not reviewer["login"]
            or type(reviewer["id"]) is not int
            or reviewer["id"] <= 0
            or reviewer["type"] not in {"User", "App"}
        ):
            raise ValueError(f"DeepSource parity {name} reviewer metadata is invalid")

    consumed_receipt_paths: set[Path] = set()

    def receipt_bytes(value: Any, name: str) -> bytes:
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
            raise ValueError(f"DeepSource parity {name} is not a receipt")
        relative, digest, size = value["path"], value["sha256"], value["bytes"]
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(size) is not int
            or size <= 0
            or size > 10_000_000
        ):
            raise ValueError(f"DeepSource parity {name} receipt is malformed")
        candidate = (evidence_root / relative).resolve()
        if evidence_root not in candidate.parents or not candidate.is_file():
            raise ValueError(f"DeepSource parity {name} receipt path is unavailable")
        if candidate in consumed_receipt_paths:
            raise ValueError(f"DeepSource parity {name} receipt path is reused")
        consumed_receipt_paths.add(candidate)
        payload = candidate.read_bytes()
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"DeepSource parity {name} receipt hash or bytes mismatch")
        return payload

    def evidence_receipt(value: Any, name: str) -> dict[str, Any]:
        payload = receipt_bytes(value, name)
        decoded = strict_json_load(payload, name)
        return semantic_object(decoded, name)

    source_payload = evidence_receipt(parity.get("source_config_receipt"), "source_config_receipt")
    require_exact_keys(
        source_payload,
        {"schema", "source", "config_digest", "analyzers", "captured_at", "reviewer"},
        "source_config_receipt",
    )
    if (
        source_payload["schema"] != "koios-ci/deepsource-source-config-v1"
        or source_payload["config_digest"] != source_config_digest
        or not isinstance(source_payload["analyzers"], list)
        or not source_payload["analyzers"]
    ):
        raise ValueError("DeepSource parity source_config_receipt semantic binding is invalid")
    analyzer_names: set[str] = set()
    for analyzer in source_payload["analyzers"]:
        analyzer = semantic_object(analyzer, "source_config_receipt.analyzer")
        require_exact_keys(analyzer, {"name", "enabled"}, "source_config_receipt.analyzer")
        if (
            not isinstance(analyzer["name"], str)
            or not analyzer["name"]
            or not isinstance(analyzer["enabled"], bool)
            or analyzer["name"] in analyzer_names
        ):
            raise ValueError("DeepSource parity source_config_receipt analyzer inventory is invalid")
        analyzer_names.add(analyzer["name"])
    validate_source(source_payload["source"], "source_config_receipt")
    validate_reviewer(source_payload["reviewer"], "source_config_receipt")
    parse_time(source_payload["captured_at"], "source_config_receipt.captured_at")

    inventory_payload = evidence_receipt(parity.get("hosted_inventory_artifact"), "hosted_inventory_artifact")
    require_exact_keys(
        inventory_payload,
        {
            "schema",
            "repository",
            "source_sha",
            "signal_ids",
            "provider_app",
            "expected_checks",
            "disabled_checks",
            "observed_at",
            "reviewer",
            "source",
        },
        "hosted_inventory_artifact",
    )
    timestamp = parity.get("hosted_inventory_observed_at")
    expected_checks = [{"name": name, "state": "success", "app": DEEPSOURCE_APP} for name in DEEPSOURCE_EXPECTED_CHECKS]
    disabled_checks = [
        {"name": name, "state": "disabled", "app": DEEPSOURCE_APP} for name in DEEPSOURCE_DISABLED_CHECKS
    ]
    if (
        inventory_payload["schema"] != "koios-ci/deepsource-hosted-inventory-v1"
        or inventory_payload["repository"] != repository
        or inventory_payload["source_sha"] != source_config_sha
        or inventory_payload["provider_app"] != DEEPSOURCE_APP
        or inventory_payload["expected_checks"] != expected_checks
        or inventory_payload["disabled_checks"] != disabled_checks
        or inventory_payload["observed_at"] != timestamp
    ):
        raise ValueError("DeepSource parity hosted App or check inventory semantic binding is invalid")
    validate_source(inventory_payload["source"], "hosted_inventory_artifact")
    validate_reviewer(inventory_payload["reviewer"], "hosted_inventory_artifact")
    parse_time(timestamp, "hosted_inventory_observed_at")

    attestation_bytes = receipt_bytes(
        parity.get("canary_execution_attestation"),
        "authenticated execution attestation",
    )
    attestation = semantic_object(
        strict_json_load(attestation_bytes, "authenticated execution attestation"),
        "authenticated execution attestation",
    )
    if canonical_json_bytes(attestation) != attestation_bytes:
        raise ValueError("DeepSource parity authenticated execution attestation is not canonical JSON")
    require_exact_keys(
        attestation,
        {
            "schema",
            "algorithm",
            "key_id",
            "public_key_sha256",
            "payload",
            "signature",
        },
        "authenticated execution attestation",
    )
    if (
        attestation["schema"] != "koios-ci/deepsource-canary-attestation-v1"
        or attestation["algorithm"] != attestation_policy["algorithm"]
        or attestation["key_id"] != attestation_policy["key_id"]
        or attestation["public_key_sha256"] != attestation_policy["public_key_sha256"]
    ):
        raise ValueError("DeepSource parity authenticated execution attestation key identity is invalid")
    signed_payload_bytes = receipt_bytes(
        attestation["payload"],
        "authenticated execution attestation payload",
    )
    if not verify_rsa_pkcs1v15_sha256(
        signed_payload_bytes,
        attestation["signature"],
        public_key,
    ):
        raise ValueError("DeepSource parity authenticated execution attestation signature is invalid")
    signed_payload = semantic_object(
        strict_json_load(signed_payload_bytes, "authenticated execution attestation payload"),
        "authenticated execution attestation payload",
    )
    if canonical_json_bytes(signed_payload) != signed_payload_bytes:
        raise ValueError("DeepSource parity authenticated execution attestation payload is not canonical JSON")
    require_exact_keys(
        signed_payload,
        {
            "schema",
            "issuer",
            "key_id",
            "repository",
            "source_sha",
            "source_config_digest",
            "issued_at",
            "canaries",
            "item_canaries",
        },
        "authenticated execution attestation payload",
    )
    if (
        signed_payload["schema"] != "koios-ci/deepsource-canary-execution-v1"
        or signed_payload["issuer"] != "koios-ci-platform-v1"
        or signed_payload["key_id"] != attestation_policy["key_id"]
        or signed_payload["repository"] != repository
        or signed_payload["source_sha"] != source_config_sha
        or signed_payload["source_config_digest"] != source_config_digest
        or signed_payload["issued_at"] != timestamp
    ):
        raise ValueError("DeepSource parity authenticated execution attestation payload binding is invalid")
    parse_time(signed_payload["issued_at"], "authenticated execution attestation issued_at")
    attested_canary_values = signed_payload["canaries"]
    if not isinstance(attested_canary_values, list):
        raise ValueError("DeepSource parity authenticated execution attestation canaries are invalid")
    attested_canaries: dict[tuple[str, str], dict[str, Any]] = {}
    expected_canary_keys = {(signal_id, kind) for signal_id in required_signal_ids for kind in ("positive", "negative")}
    for attested_canary_value in attested_canary_values:
        attested_canary = semantic_object(
            attested_canary_value,
            "authenticated execution attestation canary",
        )
        require_exact_keys(
            attested_canary,
            {
                "signal_id",
                "canary_kind",
                "owner",
                "command",
                "scope",
                "expected_exit",
                "actual_exit",
                "fixture",
                "executed_at",
                "stdout",
                "stderr",
            },
            "authenticated execution attestation canary",
        )
        attested_signal_id = attested_canary["signal_id"]
        attested_kind = attested_canary["canary_kind"]
        if not isinstance(attested_signal_id, str) or not isinstance(attested_kind, str):
            raise ValueError("DeepSource parity authenticated execution attestation canary key is invalid")
        key = (attested_signal_id, attested_kind)
        if key not in expected_canary_keys or key in attested_canaries:
            raise ValueError("DeepSource parity authenticated execution attestation canary key is invalid")
        attested_canaries[key] = attested_canary
    if set(attested_canaries) != expected_canary_keys:
        raise ValueError("DeepSource parity authenticated execution attestation canary inventory is incomplete")
    attested_item_canary_values = signed_payload["item_canaries"]
    if not isinstance(attested_item_canary_values, list):
        raise ValueError("DeepSource parity authenticated execution attestation item canaries are invalid")
    attested_item_canaries: dict[tuple[str, str], dict[str, Any]] = {}
    item_canary_fields = {
        "schema",
        "repository",
        "source_sha",
        "signal_id",
        "provider_item_id",
        "owner",
        "command",
        "fixture",
        "stdout",
        "stderr",
        "diagnostic_stream",
        "diagnostic_sha256",
        "expected_exit",
        "actual_exit",
        "executed_at",
        "attested_parent_negative_canary_sha256",
        "reviewer",
        "source",
    }
    for attested_item_value in attested_item_canary_values:
        attested_item = semantic_object(
            attested_item_value,
            "authenticated execution attestation item canary",
        )
        require_exact_keys(
            attested_item,
            item_canary_fields,
            "authenticated execution attestation item canary",
        )
        signal_id = attested_item["signal_id"]
        provider_item_id = attested_item["provider_item_id"]
        if not isinstance(signal_id, str) or not isinstance(provider_item_id, str):
            raise ValueError("DeepSource parity authenticated execution attestation item key is invalid")
        key = (signal_id, provider_item_id)
        if key in attested_item_canaries:
            raise ValueError("DeepSource parity authenticated execution attestation item key is duplicated")
        attested_item_canaries[key] = attested_item

    preconditions = parity.get("disposition_preconditions")
    if (
        not isinstance(preconditions, dict)
        or set(preconditions) != {"all_signals_proven", "live_ruleset_safe", "app_subscription_readbacks"}
        or preconditions.get("all_signals_proven") is not True
    ):
        raise ValueError("DeepSource disposition preconditions are not all proven")

    def hosted_state_readback(value: Any, name: str, schema_name: str) -> dict[str, Any]:
        readback = evidence_receipt(value, name)
        require_exact_keys(
            readback,
            {"schema", "source", "captured_at", "authentication", "reviewer", "provider", "state"},
            name,
        )
        authentication = semantic_object(readback["authentication"], f"{name}.authentication")
        provider = semantic_object(readback["provider"], f"{name}.provider")
        state = semantic_object(readback["state"], f"{name}.state")
        if (
            readback["schema"] != schema_name
            or authentication.get("authenticated") is not True
            or set(authentication) != {"authenticated", "method"}
            or authentication["method"] not in {"provider-api", "authenticated-in-app-browser"}
            or provider != {"name": "DeepSource", "app": DEEPSOURCE_APP}
        ):
            raise ValueError(f"DeepSource parity {name} authentication or provider identity is invalid")
        validate_source(readback["source"], name)
        validate_reviewer(readback["reviewer"], name)
        parse_time(readback["captured_at"], f"{name}.captured_at")
        return state

    ruleset_state = hosted_state_readback(
        preconditions.get("live_ruleset_safe"),
        "live_ruleset_safe",
        "koios-ci/deepsource-live-ruleset-readback-v1",
    )
    app_subscription_state = hosted_state_readback(
        preconditions.get("app_subscription_readbacks"),
        "app_subscription_readbacks",
        "koios-ci/deepsource-app-subscription-readback-v1",
    )
    signals = parity.get("signals")
    observed_signal_ids = (
        {signal.get("id") for signal in signals if isinstance(signal, dict)} if isinstance(signals, list) else set()
    )
    if not isinstance(signals, list) or observed_signal_ids != required_signal_ids:
        raise ValueError("DeepSource parity consumer map is incomplete")
    if len(signals) != len(required_signal_ids):
        raise ValueError("DeepSource parity contains duplicate signal IDs")
    if (
        not isinstance(inventory_payload["signal_ids"], list)
        or set(inventory_payload["signal_ids"]) != required_signal_ids
        or len(inventory_payload["signal_ids"]) != len(required_signal_ids)
    ):
        raise ValueError("DeepSource parity hosted inventory signal IDs are invalid")
    covered_profiles: set[str] = set()
    by_id = {str(signal["id"]): signal for signal in signals if isinstance(signal, dict)}
    allowed_owners = {
        "strict-mypy",
        "ruff",
        "osv-scanner",
        "gitleaks",
        "trivy",
        "platform-adapter-integrity",
        "provider-readback",
        "coverage-policy",
    }
    provider_items_by_signal: dict[str, list[str]] = {}
    for signal_id, signal in by_id.items():
        if signal.get("parity_status") != "proven" or signal.get("gaps") != []:
            raise ValueError(f"DeepSource parity {signal_id} is not proven")
        if signal.get("outcome") not in {
            "retain-unique-defense-in-depth",
            "replace-proven-duplicate",
            "disable-usage-based-ai",
        }:
            raise ValueError(f"DeepSource parity {signal_id} has no supported outcome")
        if signal_id == "ai-review-readback" and signal["outcome"] != "disable-usage-based-ai":
            raise ValueError(f"DeepSource parity {signal_id} disposition outcome is invalid")
        if signal_id != "ai-review-readback" and signal["outcome"] not in {
            "retain-unique-defense-in-depth",
            "replace-proven-duplicate",
        }:
            raise ValueError(f"DeepSource parity {signal_id} disposition outcome is invalid")
        for field in (
            "central_owner",
            "command",
            "pinned_tool_version",
            "pinned_config_digest",
            "scope",
        ):
            value = signal.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"DeepSource parity {signal_id} lacks {field}")
        if signal["central_owner"] not in allowed_owners:
            raise ValueError(f"DeepSource parity {signal_id} owner is not allowlisted")
        if not re.fullmatch(r"[0-9a-f]{64}", str(signal["pinned_config_digest"])):
            raise ValueError(f"DeepSource parity {signal_id} has invalid pinned_config_digest")
        inventory = evidence_receipt(signal.get("hosted_inventory"), f"{signal_id}.hosted_inventory")
        inventory_keys = {
            "schema",
            "repository",
            "source_sha",
            "signal_id",
            "provider_signal_id",
            "provider_app",
            "provider_check_names",
            "observed_at",
            "reviewer",
            "source",
        }
        if signal_id in {"python-static-quality", "sca"}:
            inventory_keys.add("provider_item_ids")
        require_exact_keys(
            inventory,
            inventory_keys,
            f"{signal_id}.hosted_inventory",
        )
        if (
            inventory["schema"] != "koios-ci/deepsource-signal-inventory-v1"
            or inventory["repository"] != repository
            or inventory["source_sha"] != source_config_sha
            or inventory["signal_id"] != signal_id
            or not isinstance(inventory["provider_signal_id"], str)
            or not inventory["provider_signal_id"]
            or inventory["provider_app"] != DEEPSOURCE_APP
            or inventory["provider_check_names"] != DEEPSOURCE_SIGNAL_CHECKS[signal_id]
            or inventory["observed_at"] != timestamp
        ):
            raise ValueError(f"DeepSource parity {signal_id} hosted App or check inventory binding is invalid")
        validate_source(inventory["source"], f"{signal_id}.hosted_inventory")
        validate_reviewer(inventory["reviewer"], f"{signal_id}.hosted_inventory")
        parse_time(inventory["observed_at"], f"{signal_id}.hosted_inventory.observed_at")
        if signal_id in {"python-static-quality", "sca"}:
            provider_item_ids = inventory.get("provider_item_ids")
            if (
                not isinstance(provider_item_ids, list)
                or not provider_item_ids
                or any(not isinstance(item, str) or not item for item in provider_item_ids)
                or len(set(provider_item_ids)) != len(provider_item_ids)
            ):
                raise ValueError(f"DeepSource parity {signal_id} hosted rule/capability inventory is invalid")
            provider_items_by_signal[signal_id] = provider_item_ids

        for kind in ("positive", "negative"):
            field = f"{kind}_canary"
            expectation = canary_expectations[signal_id][kind]
            canary = evidence_receipt(signal.get(field), f"{signal_id}.{field}")
            require_exact_keys(
                canary,
                {
                    "schema",
                    "signal_id",
                    "canary_kind",
                    "owner",
                    "expected_exit",
                    "actual_exit",
                    "fixture",
                    "executed_at",
                    "stdout",
                    "stderr",
                    "reviewer",
                    "source",
                },
                f"{signal_id}.{field}",
            )
            if (
                canary["schema"] != "koios-ci/deepsource-canary-result-v1"
                or canary["signal_id"] != signal_id
                or canary["canary_kind"] != kind
            ):
                raise ValueError(f"DeepSource parity {signal_id}.{field} signal_id or kind is invalid")
            owner = semantic_object(canary["owner"], f"{signal_id}.{field}.owner")
            require_exact_keys(owner, {"tool", "version", "config_digest"}, f"{signal_id}.{field}.owner")
            if owner != {
                "tool": signal["central_owner"],
                "version": signal["pinned_tool_version"],
                "config_digest": signal["pinned_config_digest"],
            }:
                raise ValueError(f"DeepSource parity {signal_id}.{field} owner version or config_digest is invalid")
            expected_exit = canary["expected_exit"]
            actual_exit = canary["actual_exit"]
            if (
                type(expected_exit) is not int
                or type(actual_exit) is not int
                or actual_exit != expected_exit
                or expected_exit != expectation["exit"]
            ):
                raise ValueError(f"DeepSource parity {signal_id}.{field} expected_exit or actual_exit is invalid")
            receipt_bytes(canary["fixture"], f"{signal_id}.{field}.fixture")
            observed_output_digests: dict[str, str] = {}
            for stream in ("stdout", "stderr"):
                output_receipt = canary[stream]
                if not isinstance(output_receipt, dict):
                    raise ValueError(f"DeepSource parity {signal_id}.{field} {stream} output is not a receipt")
                output_bytes = receipt_bytes(output_receipt, f"{signal_id}.{field}.{stream}")
                observed_output_digests[stream] = hashlib.sha256(output_bytes).hexdigest()
                if observed_output_digests[stream] != expectation[f"{stream}_sha256"]:
                    raise ValueError(
                        f"DeepSource parity {signal_id}.{field} {stream} output does not match "
                        "the platform-owned expectation"
                    )
            diagnostic_stream = expectation["diagnostic_stream"]
            if observed_output_digests[diagnostic_stream] != expectation["diagnostic_sha256"]:
                raise ValueError(f"DeepSource parity {signal_id}.{field} diagnostic proof is invalid")
            parse_time(canary["executed_at"], f"{signal_id}.{field}.executed_at")
            validate_source(canary["source"], f"{signal_id}.{field}")
            validate_reviewer(canary["reviewer"], f"{signal_id}.{field}")
            attested_canary = attested_canaries[(signal_id, kind)]
            expected_attested_canary = {
                key: canary[key]
                for key in (
                    "signal_id",
                    "canary_kind",
                    "owner",
                    "expected_exit",
                    "actual_exit",
                    "fixture",
                    "executed_at",
                    "stdout",
                    "stderr",
                )
            }
            expected_attested_canary["command"] = signal["command"]
            expected_attested_canary["scope"] = signal["scope"]
            if attested_canary != expected_attested_canary:
                raise ValueError(
                    f"DeepSource parity {signal_id}.{field} is not bound by the authenticated execution attestation"
                )
    expected_attested_item_keys = {
        (signal_id, provider_item_id)
        for signal_id in ("python-static-quality", "sca")
        for provider_item_id in provider_items_by_signal.get(signal_id, [])
    }
    if set(attested_item_canaries) != expected_attested_item_keys:
        raise ValueError(
            "DeepSource parity authenticated execution attestation item inventory does not exactly match "
            "the hosted static-rule and SCA capability inventories"
        )
    retain_deepsource = any(
        signal_id != "ai-review-readback" and signal.get("outcome") == "retain-unique-defense-in-depth"
        for signal_id, signal in by_id.items()
    )
    expected_ruleset_state = {
        "transition_safe": True,
        "required_context": "Security / required",
        "deepsource_required": retain_deepsource,
    }
    expected_app_subscription_state = (
        {
            "app_state": "retained",
            "subscription_state": "team-fixed-active",
            "usage_based_ai_enabled": False,
        }
        if retain_deepsource
        else {
            "app_state": "removed",
            "subscription_state": "cancelled",
            "usage_based_ai_enabled": False,
        }
    )
    if ruleset_state != expected_ruleset_state or app_subscription_state != expected_app_subscription_state:
        raise ValueError("DeepSource parity hosted ruleset/App/subscription readbacks contradict the disposition")

    def validate_replacement_mappings(
        signal: dict[str, Any],
        signal_id: str,
        mapping_field: str,
        expected_items: set[str],
    ) -> None:
        if signal.get("outcome") != "replace-proven-duplicate":
            return
        mappings = signal.get(mapping_field)
        if not isinstance(mappings, list) or len(mappings) != len(expected_items):
            raise ValueError(f"DeepSource parity {signal_id} replacement mapping is incomplete")
        observed_items: set[str] = set()
        for index, mapping_value in enumerate(mappings):
            mapping = semantic_object(mapping_value, f"{signal_id}.{mapping_field}[{index}]")
            require_exact_keys(
                mapping,
                {"provider_item_id", "central_owner", "negative_canary"},
                f"{signal_id}.{mapping_field}[{index}]",
            )
            provider_item_id = mapping["provider_item_id"]
            if (
                not isinstance(provider_item_id, str)
                or provider_item_id not in expected_items
                or provider_item_id in observed_items
                or mapping["central_owner"] != signal["central_owner"]
            ):
                raise ValueError(f"DeepSource parity {signal_id} replacement mapping item or owner is invalid")
            observed_items.add(provider_item_id)
            canary = evidence_receipt(
                mapping["negative_canary"],
                f"{signal_id}.{mapping_field}[{index}].negative_canary",
            )
            require_exact_keys(
                canary,
                {
                    "schema",
                    "repository",
                    "source_sha",
                    "signal_id",
                    "provider_item_id",
                    "owner",
                    "command",
                    "fixture",
                    "stdout",
                    "stderr",
                    "diagnostic_stream",
                    "expected_exit",
                    "actual_exit",
                    "executed_at",
                    "diagnostic_sha256",
                    "attested_parent_negative_canary_sha256",
                    "reviewer",
                    "source",
                },
                f"{signal_id}.{mapping_field}[{index}].negative_canary",
            )
            owner = semantic_object(canary["owner"], f"{signal_id}.{mapping_field}[{index}].owner")
            require_exact_keys(
                owner,
                {"tool", "version", "config_digest"},
                f"{signal_id}.{mapping_field}[{index}].owner",
            )
            expected_owner = {
                "tool": signal["central_owner"],
                "version": signal["pinned_tool_version"],
                "config_digest": signal["pinned_config_digest"],
            }
            output_bytes = {
                stream: receipt_bytes(
                    canary[stream],
                    f"{signal_id}.{mapping_field}[{index}].negative_canary.{stream}",
                )
                for stream in ("stdout", "stderr")
            }
            receipt_bytes(
                canary["fixture"],
                f"{signal_id}.{mapping_field}[{index}].negative_canary.fixture",
            )
            diagnostic_stream = canary["diagnostic_stream"]
            if (
                canary["schema"] != "koios-ci/deepsource-disposition-negative-canary-v1"
                or canary["repository"] != repository
                or canary["source_sha"] != source_config_sha
                or canary["signal_id"] != signal_id
                or canary["provider_item_id"] != provider_item_id
                or owner != expected_owner
                or canary["command"] != signal["command"]
                or type(canary["expected_exit"]) is not int
                or type(canary["actual_exit"]) is not int
                or canary["expected_exit"] in {0, 126, 127}
                or canary["actual_exit"] != canary["expected_exit"]
                or diagnostic_stream not in {"stdout", "stderr"}
                or not re.fullmatch(r"[0-9a-f]{64}", str(canary["diagnostic_sha256"]))
                or canary["diagnostic_sha256"] == EMPTY_SHA256
                or canary["diagnostic_sha256"]
                != hashlib.sha256(output_bytes.get(str(diagnostic_stream), b"")).hexdigest()
                or canary["attested_parent_negative_canary_sha256"] != signal["negative_canary"]["sha256"]
            ):
                raise ValueError(f"DeepSource parity {signal_id} replacement negative canary is invalid")
            parse_time(canary["executed_at"], f"{signal_id}.{mapping_field}[{index}].executed_at")
            validate_source(canary["source"], f"{signal_id}.{mapping_field}[{index}]")
            validate_reviewer(canary["reviewer"], f"{signal_id}.{mapping_field}[{index}]")
            if attested_item_canaries.get((signal_id, provider_item_id)) != canary:
                raise ValueError(
                    f"DeepSource parity {signal_id} replacement item canary is not bound by the signed attestation"
                )
        if observed_items != expected_items:
            raise ValueError(f"DeepSource parity {signal_id} replacement mapping is incomplete")

    python_static = by_id["python-static-quality"]
    if (
        not all(
            isinstance(python_static.get(field), str) and python_static[field]
            for field in ("severity_threshold", "quality_threshold")
        )
        or not isinstance(python_static.get("rule_ids"), list)
        or not python_static["rule_ids"]
        or any(not isinstance(rule_id, str) or not rule_id for rule_id in python_static["rule_ids"])
        or len(set(python_static["rule_ids"])) != len(python_static["rule_ids"])
        or python_static["rule_ids"] != provider_items_by_signal.get("python-static-quality")
    ):
        raise ValueError("DeepSource parity python-static-quality lacks hosted rule inventory")
    validate_replacement_mappings(
        python_static,
        "python-static-quality",
        "rule_mappings",
        set(python_static["rule_ids"]),
    )
    ruff = by_id["ruff-transformer"]
    ruff_fields = ("transformer_version", "ruff_version", "config_digest")
    if not all(isinstance(ruff.get(field), str) and ruff[field] for field in ruff_fields):
        raise ValueError("DeepSource parity ruff-transformer lacks version/config evidence")
    if not re.fullmatch(r"[0-9a-f]{64}", str(ruff["config_digest"])):
        raise ValueError("DeepSource parity ruff-transformer config_digest is invalid")
    sca = by_id["sca"]
    if set(provider_items_by_signal.get("sca", [])) != DEEPSOURCE_SCA_CAPABILITIES:
        raise ValueError("DeepSource parity SCA hosted capability inventory is incomplete")
    validate_replacement_mappings(sca, "sca", "capability_mappings", DEEPSOURCE_SCA_CAPABILITIES)
    manifests = sca.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("DeepSource parity has no SCA manifest coverage")
    required_manifest_profiles = {
        "requirements.txt": {"python", "critical-ml"},
        "constraints.txt": {"python", "critical-ml"},
        "requirements-core-next.txt": {"python", "critical-ml"},
        "requirements-compat-ag.txt": {"critical-ml"},
        "requirements-maintenance.txt": {"baseline", "python", "critical-ml"},
        "package-lock.json": {"node"},
        "powershell.lock.json": {"powershell"},
    }
    manifest_profiles: dict[str, set[str]] = {}
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise ValueError("DeepSource parity SCA manifest is malformed")
        if not isinstance(manifest.get("path"), str) or not manifest["path"].strip():
            raise ValueError("DeepSource parity SCA manifest lacks path")
        profiles = manifest.get("profiles")
        if not isinstance(profiles, list) or not set(profiles) <= PROFILES or not profiles:
            raise ValueError("DeepSource parity SCA manifest profiles are invalid")
        if manifest["path"] in manifest_profiles:
            raise ValueError("DeepSource parity SCA manifest path is duplicated")
        manifest_profiles[manifest["path"]] = set(profiles)
        covered_profiles.update(profiles)
        graph = evidence_receipt(manifest.get("resolved_graph"), "sca.resolved_graph")
        require_exact_keys(
            graph,
            {"schema", "manifest", "profiles", "source", "packages"},
            "sca.resolved_graph",
        )
        if (
            graph["schema"] != "koios-ci/resolved-dependency-graph-v1"
            or graph["manifest"] != manifest["path"]
            or graph["profiles"] != profiles
            or not isinstance(graph["packages"], list)
            or not graph["packages"]
        ):
            raise ValueError("DeepSource parity SCA resolved graph manifest/profile binding is invalid")
        validate_source(graph["source"], "sca.resolved_graph")
        packages: list[dict[str, str]] = []
        for package in graph["packages"]:
            package = semantic_object(package, "sca.resolved_graph.package")
            require_exact_keys(package, {"name", "version", "purl"}, "sca.resolved_graph.package")
            if not all(isinstance(package[key], str) and package[key] for key in package):
                raise ValueError("DeepSource parity SCA resolved package is invalid")
            packages.append(package)
        sbom = evidence_receipt(manifest.get("sbom"), "sca.sbom")
        if (
            sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") not in {"1.5", "1.6"}
            or not isinstance(sbom.get("version"), int)
            or sbom["version"] < 1
            or not isinstance(sbom.get("metadata"), dict)
            or not isinstance(sbom.get("components"), list)
        ):
            raise ValueError("DeepSource parity SCA SBOM is not valid CycloneDX-shaped evidence")
        properties = sbom["metadata"].get("properties")
        expected_properties = [
            {"name": "koios:manifest", "value": manifest["path"]},
            {"name": "koios:profiles", "value": ",".join(profiles)},
        ]
        if properties != expected_properties:
            raise ValueError("DeepSource parity SCA SBOM manifest/profile binding is invalid")
        sbom_packages = [
            {key: component.get(key) for key in ("name", "version", "purl")}
            for component in sbom["components"]
            if isinstance(component, dict) and component.get("type") == "library"
        ]
        if sbom_packages != packages:
            raise ValueError("DeepSource parity SCA graph and SBOM resolved packages differ")
    if sca.get("canonical_constraints") != "constraints.txt":
        raise ValueError("DeepSource parity SCA canonical constraints binding is invalid")
    if any(manifest_profiles.get(path) != profiles for path, profiles in required_manifest_profiles.items()):
        raise ValueError("DeepSource parity SCA core-next, compat-ag, or maintenance manifest closure is incomplete")
    optional_conda_surfaces = sca.get("optional_conda_surfaces")
    if not isinstance(optional_conda_surfaces, list) or len(optional_conda_surfaces) != 3:
        raise ValueError("DeepSource parity optional Conda surface inventory is incomplete")
    conda_presence: dict[str, bool] = {}
    for surface in optional_conda_surfaces:
        if (
            not isinstance(surface, dict)
            or set(surface) != {"path", "present"}
            or surface.get("path") in conda_presence
            or type(surface.get("present")) is not bool
        ):
            raise ValueError("DeepSource parity optional Conda surface inventory is invalid")
        conda_presence[str(surface["path"])] = surface["present"]
    if set(conda_presence) != {"environment.yml", "environment.yaml", "conda-lock.yml"}:
        raise ValueError("DeepSource parity optional Conda surface inventory is invalid")
    if any((path in manifest_profiles) != present for path, present in conda_presence.items()):
        raise ValueError("DeepSource parity present Conda surface lacks SCA evidence")
    if covered_profiles != PROFILES:
        raise ValueError("DeepSource parity does not cover every active profile")
    secrets = by_id["secrets"]
    if (
        not isinstance(secrets.get("scan_scope"), list)
        or not secrets["scan_scope"]
        or not isinstance(secrets.get("provider_trigger_gaps"), list)
        or set(secrets["provider_trigger_gaps"]) != {"documentation", "configuration"}
        or len(secrets["provider_trigger_gaps"]) != 2
    ):
        raise ValueError("DeepSource parity secrets lacks scan scope or docs/config provider trigger gaps")
    docker = by_id["docker-compose-config"]
    if not isinstance(docker.get("config_scope"), list) or not docker["config_scope"]:
        raise ValueError("DeepSource parity Docker/Compose/config scope is absent")
    adapter = by_id["adapter-integrity"]
    if adapter.get("hosted_app") != DEEPSOURCE_APP or not re.fullmatch(
        r"[0-9a-f]{64}", str(adapter.get("adapter_contract_digest"))
    ):
        raise ValueError("DeepSource parity adapter-integrity App or contract binding is invalid")
    ai_review = by_id["ai-review-readback"]
    if (
        ai_review.get("outcome") != "disable-usage-based-ai"
        or ai_review.get("enabled_readback") is not False
        or ai_review.get("disabled_readback") is not True
    ):
        raise ValueError("DeepSource parity AI Review must prove disabled state")
    for readback_type in ("app", "subscription", "target"):
        field = f"{readback_type}_readback"
        readback = evidence_receipt(ai_review.get(field), f"ai-review-readback.{field}")
        require_exact_keys(
            readback,
            {"schema", "repository", "signal_id", "observed_at", "state", "reviewer", "source"},
            f"ai-review-readback.{field}",
        )
        state = semantic_object(readback["state"], f"ai-review-readback.{field}.state")
        if (
            readback["schema"] != f"koios-ci/deepsource-{readback_type}-readback-v1"
            or readback["repository"] != repository
            or readback["signal_id"] != "ai-review-readback"
            or readback["observed_at"] != timestamp
            or state != {"enabled": False}
        ):
            raise ValueError(f"DeepSource parity AI Review {field} contradicts disabled state")
        validate_source(readback["source"], f"ai-review-readback.{field}")
        validate_reviewer(readback["reviewer"], f"ai-review-readback.{field}")
        parse_time(readback["observed_at"], f"ai-review-readback.{field}.observed_at")
    coverage = by_id["coverage"]
    if not isinstance(coverage.get("applicable"), bool):
        raise ValueError("DeepSource parity coverage applicability is absent")
    if coverage["applicable"] is False and not isinstance(coverage.get("not_applicable_reason"), str):
        raise ValueError("DeepSource parity coverage not-applicable readback is absent")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--as-of")
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="Validate checked-in structure without claiming hosted parity evidence.",
    )
    args = parser.parse_args()
    try:
        raw_as_of = args.as_of or dt.datetime.now(dt.UTC).isoformat()
        as_of = dt.datetime.fromisoformat(raw_as_of.replace("Z", "+00:00"))
        if as_of.tzinfo is None:
            raise ValueError("--as-of must include a timezone")
        validate_workflow(args.root)
        validate_profile_contract(args.root, as_of=as_of)
        validate_common_security(args.root)
        validate_quality_map(args.root)
        if args.structural_only:
            schema = json.loads((args.root / "contract/deepsource-parity-v1.schema.json").read_text(encoding="utf-8"))
            parity = json.loads(
                (args.root / "templates/consumer/.github/ci-platform-deepsource-parity.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.Draft202012Validator(schema).validate(parity)
        else:
            validate_deepsource_parity(args.root, as_of=as_of)
        validate_publication_boundary(args.root)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("LOCAL STRUCTURAL VALIDATION ONLY: independent hosted/evidence review remains required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
