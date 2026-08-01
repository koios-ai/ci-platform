"""Byte-level verification for the final CI evidence bundle."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMPONENTS = {
    "changed_files_evidence_digest": "changed-files.json",
    "coverage_sha256": "coverage.xml",
    "coverage_json_digest": "coverage.json",
    "coverage_summary_digest": "coverage-summary.json",
    "typing_summary_digest": "typing-summary.json",
    "documentation_summary_digest": "documentation-summary.json",
    "environment_summary_digest": "environment-summary.json",
    "critical_safety_summary_digest": "critical-safety-summary.json",
    "smoke_summary_digest": "smoke-summary.json",
    "test_policy_summary_digest": "test-policy-summary.json",
    "repository_pre_hooks_digest": "repository-pre-hooks-summary.json",
    "repository_post_hooks_digest": "repository-post-hooks-summary.json",
    "policy_non_regression_digest": "policy-non-regression-summary.json",
    "pytest_junit_digest": "pytest-junit.xml",
}
SUMMARY_STATUS = {
    "coverage-summary.json": {"passed"},
    "typing-summary.json": {"passed"},
    "documentation-summary.json": {"passed"},
    "environment-summary.json": {"passed"},
    "critical-safety-summary.json": {"passed", "not-applicable"},
    "smoke-summary.json": {"passed"},
    "test-policy-summary.json": {"passed"},
    "repository-pre-hooks-summary.json": {"passed"},
    "repository-post-hooks-summary.json": {"passed"},
    "policy-non-regression-summary.json": {"passed"},
}


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_evidence(
    root: pathlib.Path,
    expected_head_sha: str,
    expected_manifest_digest: str,
    expected_platform_sha: str,
) -> dict[str, Any]:
    if not FULL_SHA.fullmatch(expected_head_sha):
        raise ValueError("expected head is not a full lowercase SHA")
    if not FULL_SHA.fullmatch(expected_platform_sha):
        raise ValueError("expected platform ref is not an immutable full SHA")
    if not DIGEST.fullmatch(expected_manifest_digest):
        raise ValueError("expected evidence digest is malformed")
    expected_files = {"evidence-manifest.json", *COMPONENTS.values()}
    observed_files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"evidence tree contains a non-regular entry: {relative}")
        observed_files.add(relative)
    if observed_files != expected_files:
        raise ValueError(
            f"evidence tree differs from the exact file allowlist: {sorted(observed_files ^ expected_files)}"
        )
    manifest_path = root / "evidence-manifest.json"
    if not manifest_path.is_file():
        raise ValueError("evidence manifest is missing")
    if _sha256(manifest_path) != expected_manifest_digest:
        raise ValueError("evidence manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("evidence manifest is malformed")
    if manifest.get("head_sha") != expected_head_sha:
        raise ValueError("evidence head does not match the current pull request")
    if manifest.get("platform_sha") != expected_platform_sha:
        raise ValueError("evidence platform SHA does not match the pinned verifier")
    for key in ("base_sha", "platform_sha"):
        if not isinstance(manifest.get(key), str) or not FULL_SHA.fullmatch(manifest[key]):
            raise ValueError(f"malformed manifest SHA: {key}")
    for key in ("changed_files_digest", "quality_debt_digest", "security_evidence_digest"):
        if not isinstance(manifest.get(key), str) or not DIGEST.fullmatch(manifest[key]):
            raise ValueError(f"malformed manifest digest: {key}")
    if manifest.get("profile") not in {"baseline", "python", "node", "powershell", "critical-ml"}:
        raise ValueError("malformed manifest profile")

    for field, filename in COMPONENTS.items():
        path = root / filename
        if not path.is_file():
            raise ValueError(f"missing evidence component: {filename}")
        if _sha256(path) != manifest.get(field):
            raise ValueError(f"evidence component digest mismatch: {filename}")
        allowed = SUMMARY_STATUS.get(filename)
        if allowed is not None:
            summary = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(summary, Mapping) or summary.get("status") not in allowed:
                raise ValueError(f"evidence component did not pass: {filename}")
        if filename == "pytest-junit.xml":
            junit = path.read_bytes()
            if len(junit) > 10_000_000 or b"<!DOCTYPE" in junit.upper() or b"<!ENTITY" in junit.upper():
                raise ValueError("pytest JUnit evidence contains unsafe XML")
            # The byte ceiling and explicit DTD/entity rejection close the XML
            # attack surface before ElementTree sees the untrusted artifact.
            root_element = ET.fromstring(junit)  # nosec B314
            suites = [root_element] if root_element.tag == "testsuite" else list(root_element.findall("testsuite"))
            if not suites:
                # Baseline evidence uses a zero-test testsuites root.
                if root_element.tag != "testsuites":
                    raise ValueError("pytest JUnit evidence is malformed")
                suites = [root_element]
            for suite in suites:
                if any(int(suite.attrib.get(field, "0")) != 0 for field in ("errors", "failures", "skipped")):
                    raise ValueError("pytest JUnit evidence is not fully green")
    changed_files = json.loads((root / "changed-files.json").read_text(encoding="utf-8"))
    if (
        not isinstance(changed_files, list)
        or any(not isinstance(path, str) or not path for path in changed_files)
        or changed_files != sorted(set(changed_files))
    ):
        raise ValueError("changed-file evidence is malformed")
    canonical_changed_files = "".join(f"{path}\n" for path in changed_files).encode("utf-8")
    if hashlib.sha256(canonical_changed_files).hexdigest() != manifest["changed_files_digest"]:
        raise ValueError("changed-file semantic digest mismatch")
    return manifest


def main() -> None:
    manifest = verify_evidence(
        pathlib.Path.cwd(),
        os.environ["INPUT_EXPECTED_HEAD_SHA"],
        os.environ["INPUT_EXPECTED_EVIDENCE_DIGEST"],
        os.environ["EXPECTED_PLATFORM_SHA"],
    )
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("verified=true\n")
        output.write(f"profile={manifest['profile']}\n")


if __name__ == "__main__":
    main()
