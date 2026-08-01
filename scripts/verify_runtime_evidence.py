"""Fresh-job verification of bounded runtime evidence treated strictly as data."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

MAX_FILE_BYTES = 10_000_000
MAX_BUNDLE_BYTES = 25_000_000
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_NODE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:cjs|js|mjs)$")
PYTHON_EVIDENCE_FILES = {
    "coverage.json",
    "coverage.xml",
    "critical-safety-summary.json",
    "pytest-junit.xml",
    "test-policy-summary.json",
}
NODE_EVIDENCE_FILES = {"node-test-summary.json", "node-test.tap"}
POWERSHELL_EVIDENCE_FILES = {"pester-results.xml"}
BASELINE_EVIDENCE_FILES = {"runtime-not-applicable.json"}
NODE_POLICY_PATH = ".github/ci-platform-node-test-policy.json"


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _json(path: pathlib.Path) -> Mapping[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"runtime JSON evidence is missing: {path.name}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
        raise ValueError(f"runtime JSON evidence is missing or oversized: {path.name}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"runtime JSON evidence is malformed: {path.name}") from error
    if not isinstance(value, Mapping):
        raise ValueError(f"runtime JSON evidence must be an object: {path.name}")
    return value


def validate_bundle(root: pathlib.Path, allowlist: set[str]) -> None:
    """Require exactly the bounded, regular evidence files for one profile."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("runtime evidence directory is missing")
    observed: set[str] = set()
    total = 0
    for path in sorted(root.iterdir()):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError("runtime evidence entry is unavailable") from error
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("runtime evidence contains a non-regular entry")
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError("runtime evidence entry escapes its root")
        relative = path.name
        observed.add(relative)
        size = metadata.st_size
        if size > MAX_FILE_BYTES:
            raise ValueError(f"runtime evidence file is oversized: {relative}")
        total += size
    expected = set(allowlist)
    if "runtime-attestation.json" in observed:
        expected.add("runtime-attestation.json")
    if observed != expected:
        raise ValueError(f"runtime evidence differs from the closed allowlist: {sorted(observed ^ expected)}")
    if total > MAX_BUNDLE_BYTES:
        raise ValueError("runtime evidence bundle is oversized")


def _junit_counts(path: pathlib.Path) -> dict[str, int]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_FILE_BYTES or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("runtime JUnit evidence is unsafe")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise ValueError("runtime JUnit evidence is malformed") from error
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites and root.tag == "testsuites":
        suites = [root]
    if not suites:
        raise ValueError("runtime JUnit evidence has no suite")
    counts = {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("errors", "failures", "skipped", "tests")
    }
    if counts["tests"] <= 0:
        raise ValueError("runtime evidence reports zero executed tests")
    if counts["errors"] or counts["failures"] or counts["skipped"]:
        raise ValueError(f"runtime evidence is not fully green: {counts}")
    return counts


def verify_python_evidence(
    evidence: pathlib.Path,
    *,
    profile: str,
    base_sha: str,
) -> dict[str, int]:
    if profile not in {"python", "critical-ml"} or not FULL_SHA.fullmatch(base_sha):
        raise ValueError("Python runtime verification inputs are invalid")
    validate_bundle(evidence, PYTHON_EVIDENCE_FILES)
    counts = _junit_counts(evidence / "pytest-junit.xml")
    summary = _json(evidence / "test-policy-summary.json")
    expected_keys = {
        "base_sha",
        "critical_command",
        "disabled_plugins",
        "full_command",
        "marker_exclusions",
        "policy_digest",
        "profile",
        "protected_support_files",
        "registered_markers",
        "test_counts",
        "test_roots",
        "unexpected_skip_policy",
        "status",
    }
    if set(summary) != expected_keys:
        raise ValueError("test-policy summary has an open schema")
    if (
        summary["base_sha"] != base_sha
        or summary["profile"] != profile
        or summary["status"] != "passed"
        or summary["unexpected_skip_policy"] != "fail"
        or summary["test_counts"] != counts
        or not isinstance(summary["policy_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", summary["policy_digest"])
    ):
        raise ValueError("test-policy summary is not bound to the verified runtime")
    critical = _json(evidence / "critical-safety-summary.json")
    if profile == "critical-ml":
        required = {
            "categories",
            "collected_by_file",
            "collection_digest",
            "collection_test_count",
            "junit_digest",
            "profile",
            "selected_tests",
            "status",
            "test_counts",
        }
        per_file = critical.get("collected_by_file")
        if (
            set(critical) != required
            or critical.get("status") != "passed"
            or critical.get("profile") != profile
            or not isinstance(per_file, Mapping)
            or not per_file
            or any(type(value) is not int or value <= 0 for value in per_file.values())
            or critical.get("collection_test_count") != sum(per_file.values())
            or critical.get("test_counts", {}).get("tests") != sum(per_file.values())
        ):
            raise ValueError("critical runtime evidence is incomplete")
    elif critical != {
        "categories": {},
        "profile": profile,
        "selected_tests": [],
        "status": "not-applicable",
    }:
        raise ValueError("ordinary Python runtime has invalid critical evidence")
    return counts


def validate_node_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"adapter", "test_files", "unexpected_skip_policy", "version"}
    if set(value) != expected or value.get("version") != 1 or value.get("adapter") != "node-test":
        raise ValueError("Node test policy has an open or unsupported schema")
    if value.get("unexpected_skip_policy") != "fail":
        raise ValueError("Node test policy must fail unexpected skips")
    files = value.get("test_files")
    if (
        not isinstance(files, list)
        or not files
        or len(files) > 128
        or len(set(files)) != len(files)
        or files != sorted(files)
        or any(not isinstance(path, str) or not SAFE_NODE_PATH.fullmatch(path) for path in files)
    ):
        raise ValueError("Node test policy requires bounded explicit sorted test files")
    return {
        "version": 1,
        "adapter": "node-test",
        "test_files": list(files),
        "unexpected_skip_policy": "fail",
    }


def load_node_policy_from_base(root: pathlib.Path, base_sha: str) -> dict[str, Any]:
    if not FULL_SHA.fullmatch(base_sha):
        raise ValueError("protected-base SHA is malformed")
    root = root.resolve()
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{base_sha}:{NODE_POLICY_PATH}"],
            cwd=root,
            stderr=subprocess.PIPE,
        )
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
    except (subprocess.CalledProcessError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("protected-base Node test policy is unavailable") from error
    if not isinstance(value, Mapping):
        raise ValueError("protected-base Node test policy root is invalid")
    policy = validate_node_policy(value)
    missing: list[str] = []
    for relative in policy["test_files"]:
        path = root / pathlib.PurePosixPath(relative)
        try:
            metadata = path.lstat()
        except OSError:
            missing.append(relative)
            continue
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or root not in resolved.parents:
            missing.append(relative)
    if missing:
        raise ValueError(f"declared Node test file is absent or non-regular at the candidate head: {missing}")
    return policy


def _node_counts(value: Any, label: str) -> dict[str, int]:
    expected = {"failed", "passed", "skipped", "tests", "todo"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{label} Node counts have an open schema")
    counts = dict(value)
    if any(type(item) is not int or item < 0 for item in counts.values()):
        raise ValueError(f"{label} Node counts are invalid")
    if (
        counts["tests"] <= 0
        or counts["passed"] != counts["tests"]
        or counts["failed"]
        or counts["skipped"]
        or counts["todo"]
    ):
        raise ValueError(f"{label} Node tests are not fully green")
    return counts


def verify_node_evidence(evidence: pathlib.Path, policy: Mapping[str, Any]) -> None:
    policy = validate_node_policy(policy)
    validate_bundle(evidence, NODE_EVIDENCE_FILES)
    summary = _json(evidence / "node-test-summary.json")
    expected = {"adapter", "per_file", "schema_version", "status", "test_files", "totals"}
    if (
        set(summary) != expected
        or summary.get("schema_version") != 1
        or summary.get("adapter") != "node-test"
        or summary.get("status") != "passed"
        or summary.get("test_files") != policy["test_files"]
    ):
        raise ValueError("Node test summary is not bound to the protected policy")
    per_file = summary.get("per_file")
    if not isinstance(per_file, Mapping) or set(per_file) != set(policy["test_files"]):
        raise ValueError("Node runtime did not execute every declared test file")
    parsed = [_node_counts(per_file[path], path) for path in policy["test_files"]]
    totals = _node_counts(summary.get("totals"), "aggregate")
    recomputed = {key: sum(item[key] for item in parsed) for key in totals}
    if totals != recomputed:
        raise ValueError("Node aggregate counts do not match per-file evidence")
    raw_tap = (evidence / "node-test.tap").read_bytes()
    if not raw_tap or len(raw_tap) > MAX_FILE_BYTES:
        raise ValueError("Node TAP evidence is missing or oversized")
    try:
        tap = raw_tap.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Node TAP evidence is not UTF-8") from error
    headings = list(re.finditer(r"(?m)^### ([^\r\n]+)\r?$", tap))
    if [match.group(1) for match in headings] != policy["test_files"]:
        raise ValueError("Node TAP does not cover every declared file in protected order")
    for index, match in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(tap)
        block = tap[match.end() : end]
        values: dict[str, int] = {}
        for tap_name, summary_name in (
            ("tests", "tests"),
            ("pass", "passed"),
            ("fail", "failed"),
            ("skipped", "skipped"),
            ("todo", "todo"),
        ):
            matches = re.findall(rf"(?m)^# {tap_name} (\d+)\r?$", block)
            if len(matches) != 1:
                raise ValueError(f"Node TAP has no unique {tap_name} count for {match.group(1)}")
            values[summary_name] = int(matches[0])
        if values != per_file[match.group(1)]:
            raise ValueError(f"Node TAP counts differ from summary for {match.group(1)}")


def verify_powershell_evidence(evidence: pathlib.Path) -> None:
    validate_bundle(evidence, POWERSHELL_EVIDENCE_FILES)
    _junit_counts(evidence / "pester-results.xml")


def verify_baseline_evidence(evidence: pathlib.Path) -> None:
    validate_bundle(evidence, BASELINE_EVIDENCE_FILES)
    value = _json(evidence / "runtime-not-applicable.json")
    if value != {"profile": "baseline", "reason": "no runtime tests", "status": "not-applicable"}:
        raise ValueError("baseline runtime N/A evidence is invalid")


def verify_attestation(
    evidence: pathlib.Path,
    payload_files: set[str],
    *,
    profile: str,
    base_sha: str,
    head_sha: str,
    platform_sha: str,
    workflow_attempt: int,
    policy_digest: str,
) -> str:
    validate_bundle(evidence, payload_files)
    if not (evidence / "runtime-attestation.json").is_file():
        raise ValueError("runtime attestation is missing")
    value = _json(evidence / "runtime-attestation.json")
    expected_keys = {
        "base_sha",
        "evidence_sha256",
        "head_sha",
        "image_digest",
        "platform_sha",
        "policy_digest",
        "profile",
        "schema_version",
        "status",
        "workflow_attempt",
    }
    if set(value) != expected_keys:
        raise ValueError("runtime attestation has an open schema")
    expected_provenance = {
        "profile": profile,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "platform_sha": platform_sha,
        "workflow_attempt": workflow_attempt,
        "policy_digest": policy_digest,
    }
    if any(value.get(key) != expected for key, expected in expected_provenance.items()):
        raise ValueError("runtime attestation provenance does not match the fresh verifier")
    if value.get("schema_version") != 1 or value.get("status") != "captured-after-target-exit":
        raise ValueError("runtime attestation capture status is invalid")
    image_digest = value.get("image_digest")
    if not isinstance(image_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ValueError("runtime attestation image digest is invalid")
    hashes = value.get("evidence_sha256")
    if not isinstance(hashes, Mapping) or set(hashes) != payload_files:
        raise ValueError("runtime attestation evidence digest inventory is incomplete")
    for relative in payload_files:
        actual = hashlib.sha256((evidence / relative).read_bytes()).hexdigest()
        if hashes[relative] != actual:
            raise ValueError(f"runtime evidence digest mismatch: {relative}")
    return image_digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--profile", choices=("baseline", "python", "node", "powershell", "critical-ml"), required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--platform-sha", required=True)
    parser.add_argument("--workflow-attempt", type=int, required=True)
    parser.add_argument("--coverage-output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not FULL_SHA.fullmatch(args.head_sha) or not FULL_SHA.fullmatch(args.platform_sha):
        raise ValueError("candidate or platform SHA is malformed")
    checkout_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.root, text=True).strip()
    if checkout_head != args.head_sha:
        raise ValueError("fresh verifier checkout HEAD does not match runtime provenance")
    if args.profile in {"python", "critical-ml"}:
        verify_python_evidence(args.evidence_dir, profile=args.profile, base_sha=args.base_sha)
        summary = _json(args.evidence_dir / "test-policy-summary.json")
        verify_attestation(
            args.evidence_dir,
            PYTHON_EVIDENCE_FILES,
            profile=args.profile,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            platform_sha=args.platform_sha,
            workflow_attempt=args.workflow_attempt,
            policy_digest=str(summary["policy_digest"]),
        )
        subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).with_name("evaluate_coverage.py")),
                "--coverage-json",
                str(args.evidence_dir / "coverage.json"),
                "--base-sha",
                args.base_sha,
                "--head-sha",
                args.head_sha,
                "--profile",
                args.profile,
                "--output",
                str(args.coverage_output),
            ],
            cwd=args.root,
            check=True,
            timeout=300,
        )
    elif args.profile == "node":
        policy = load_node_policy_from_base(args.root, args.base_sha)
        verify_node_evidence(args.evidence_dir, policy)
        verify_attestation(
            args.evidence_dir,
            NODE_EVIDENCE_FILES,
            profile=args.profile,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            platform_sha=args.platform_sha,
            workflow_attempt=args.workflow_attempt,
            policy_digest=hashlib.sha256(
                (json.dumps(policy, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            ).hexdigest(),
        )
    elif args.profile == "powershell":
        verify_powershell_evidence(args.evidence_dir)
        verify_attestation(
            args.evidence_dir,
            POWERSHELL_EVIDENCE_FILES,
            profile=args.profile,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            platform_sha=args.platform_sha,
            workflow_attempt=args.workflow_attempt,
            policy_digest=hashlib.sha256(b"pester-all-tests-v1\n").hexdigest(),
        )
    else:
        verify_baseline_evidence(args.evidence_dir)
        verify_attestation(
            args.evidence_dir,
            BASELINE_EVIDENCE_FILES,
            profile=args.profile,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            platform_sha=args.platform_sha,
            workflow_attempt=args.workflow_attempt,
            policy_digest=hashlib.sha256(b"baseline-runtime-not-applicable-v1\n").hexdigest(),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
