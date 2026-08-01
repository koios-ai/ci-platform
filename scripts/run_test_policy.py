"""Execute the protected-base declarative test policy against the PR head."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

from test_policy import (
    CRITICAL_CATEGORIES,
    build_critical_command,
    build_pytest_command,
    load_policy_from_base,
    load_policy_from_protected_manifest,
    pytest_subprocess_environment,
    remove_pytest_basetemp,
    validate_profile_policy,
)

MAX_JUNIT_BYTES = 10_000_000
MAX_COLLECTION_BYTES = 10_000_000
MAX_CRITICAL_NODES = 100_000


def _write_json(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _junit_counts(path: pathlib.Path, *, require_nonzero: bool = True) -> dict[str, int]:
    if not path.is_file():
        raise ValueError(f"pytest JUnit evidence is missing: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_JUNIT_BYTES or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("pytest JUnit evidence contains unsafe XML")
    root = ET.fromstring(raw)  # nosec B314
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        if root.tag != "testsuites":
            raise ValueError("pytest JUnit evidence is malformed")
        suites = [root]
    counts = {
        field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
        for field in ("errors", "failures", "skipped", "tests")
    }
    if counts["errors"] or counts["failures"] or counts["skipped"]:
        raise ValueError(
            "pytest JUnit is not fully green with zero unexpected skips: " + json.dumps(counts, sort_keys=True)
        )
    if require_nonzero and counts["tests"] <= 0:
        raise ValueError("pytest JUnit contains zero executed tests")
    return counts


def _write_baseline_outputs(
    *,
    coverage_xml: pathlib.Path,
    coverage_json: pathlib.Path,
    junit_path: pathlib.Path,
) -> None:
    coverage_xml.write_text(
        '<?xml version="1.0" ?><coverage version="n/a" lines-valid="0" lines-covered="0" line-rate="1.0"></coverage>\n',
        encoding="utf-8",
    )
    _write_json(
        coverage_json,
        {
            "files": {},
            "meta": {"profile": "baseline"},
            "totals": {"percent_covered": 100.0},
        },
    )
    junit_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites tests="0" failures="0" errors="0" skipped="0"/>\n',
        encoding="utf-8",
    )


def _pytest_environment() -> dict[str, str]:
    """Remove caller-controlled pytest selectors from the critical rerun."""
    return pytest_subprocess_environment()


def _critical_collection(
    output: bytes,
    selected_tests: list[str],
) -> tuple[list[str], dict[str, int]]:
    if len(output) > MAX_COLLECTION_BYTES:
        raise ValueError("critical pytest collection output exceeds the evidence limit")
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("critical pytest collection output is not UTF-8") from error
    selected = set(selected_tests)
    nodeids: list[str] = []
    counts = {path: 0 for path in selected_tests}
    for line in lines:
        if "::" not in line:
            continue
        nodeid = line.strip().replace("\\", "/")
        relative = nodeid.split("::", 1)[0]
        if relative not in selected:
            raise ValueError(f"critical pytest collected an undeclared path: {relative}")
        nodeids.append(nodeid)
        counts[relative] += 1
    if not nodeids or len(nodeids) > MAX_CRITICAL_NODES:
        raise ValueError("critical pytest collection is empty or exceeds the node limit")
    if len(set(nodeids)) != len(nodeids):
        raise ValueError("critical pytest collection contains duplicate node IDs")
    empty = sorted(path for path, count in counts.items() if count == 0)
    if empty:
        raise ValueError("every protected critical test file must collect at least one test: " + ", ".join(empty))
    return sorted(nodeids), counts


def run_policy(
    *,
    root: pathlib.Path,
    base_sha: str,
    profile: str,
    evidence_dir: pathlib.Path,
    coverage_xml: pathlib.Path,
    coverage_json: pathlib.Path,
    trusted_site: pathlib.Path,
    target_site: pathlib.Path | None = None,
    protected_base_manifest: pathlib.Path | None = None,
    protected_pytest_config: pathlib.Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    trusted_site = trusted_site.resolve()
    if not trusted_site.is_dir():
        raise ValueError("trusted pytest site-packages path is unavailable")
    evidence_dir = evidence_dir.resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    coverage_xml = coverage_xml.resolve()
    coverage_json = coverage_json.resolve()
    junit_path = evidence_dir / "pytest-junit.xml"
    if protected_base_manifest is None:
        policy, policy_digest = load_policy_from_base(root, base_sha)
    else:
        policy, policy_digest = load_policy_from_protected_manifest(root, protected_base_manifest, base_sha)
    validate_profile_policy(policy, profile)

    full_command: list[str] = []
    critical_command: list[str] = []
    critical_summary: dict[str, Any]
    if profile == "baseline":
        _write_baseline_outputs(
            coverage_xml=coverage_xml,
            coverage_json=coverage_json,
            junit_path=junit_path,
        )
        full_counts = _junit_counts(junit_path, require_nonzero=False)
        critical_summary = {
            "categories": {},
            "profile": profile,
            "selected_tests": [],
            "status": "not-applicable",
        }
    else:
        runtime_environment = _pytest_environment()
        coverage_data = evidence_dir / ".coverage-runtime"
        runtime_environment["COVERAGE_FILE"] = str(coverage_data)
        full_command = build_pytest_command(
            policy,
            junit_path=junit_path,
            coverage_xml=coverage_xml,
            coverage_json=coverage_json,
            trusted_site=trusted_site,
            target_root=root,
            target_site=target_site,
            protected_pytest_config=protected_pytest_config,
        )
        try:
            subprocess.run(
                full_command,
                cwd=root,
                check=True,
                timeout=3600,
                env=runtime_environment,
            )
        finally:
            remove_pytest_basetemp(junit_path, "full")
        full_counts = _junit_counts(junit_path)
        if profile == "critical-ml":
            critical_junit = coverage_xml.parent / ".ci-platform-critical-pytest-junit.xml"
            selected = [path for category in sorted(CRITICAL_CATEGORIES) for path in policy["critical_tests"][category]]
            collect_command = build_critical_command(
                policy,
                junit_path=critical_junit,
                trusted_site=trusted_site,
                collect_only=True,
                target_root=root,
                target_site=target_site,
                protected_pytest_config=protected_pytest_config,
            )
            try:
                collection = subprocess.run(
                    collect_command,
                    cwd=root,
                    check=True,
                    timeout=600,
                    env=_pytest_environment(),
                    capture_output=True,
                )
            finally:
                remove_pytest_basetemp(critical_junit, "critical")
            collected_nodeids, collected_by_file = _critical_collection(
                collection.stdout,
                selected,
            )
            critical_command = build_critical_command(
                policy,
                junit_path=critical_junit,
                trusted_site=trusted_site,
                target_root=root,
                target_site=target_site,
                protected_pytest_config=protected_pytest_config,
            )
            try:
                subprocess.run(
                    critical_command,
                    cwd=root,
                    check=True,
                    timeout=1800,
                    env=_pytest_environment(),
                )
            finally:
                remove_pytest_basetemp(critical_junit, "critical")
            critical_counts = _junit_counts(critical_junit)
            if critical_counts["tests"] != len(collected_nodeids):
                raise ValueError(
                    "critical pytest did not execute every collected protected node: "
                    f"collected={len(collected_nodeids)} executed={critical_counts['tests']}"
                )
            critical_summary = {
                "categories": policy["critical_tests"],
                "collected_by_file": collected_by_file,
                "collection_digest": hashlib.sha256(
                    "".join(f"{nodeid}\n" for nodeid in collected_nodeids).encode("utf-8")
                ).hexdigest(),
                "collection_test_count": len(collected_nodeids),
                "junit_digest": hashlib.sha256(critical_junit.read_bytes()).hexdigest(),
                "profile": profile,
                "selected_tests": selected,
                "test_counts": critical_counts,
                "status": "passed",
            }
            critical_junit.unlink()
        else:
            critical_summary = {
                "categories": {},
                "profile": profile,
                "selected_tests": [],
                "status": "not-applicable",
            }
        coverage_data.unlink(missing_ok=True)

    _write_json(
        evidence_dir / "critical-safety-summary.json",
        critical_summary,
    )
    summary = {
        "base_sha": base_sha,
        "critical_command": critical_command,
        "disabled_plugins": policy["disabled_plugins"],
        "full_command": full_command,
        "marker_exclusions": policy["marker_exclusions"],
        "registered_markers": policy["registered_markers"],
        "policy_digest": policy_digest,
        "profile": profile,
        "protected_support_files": policy["protected_support_files"],
        "test_counts": full_counts,
        "test_roots": policy["test_roots"],
        "unexpected_skip_policy": policy["unexpected_skip_policy"],
        "status": "passed",
    }
    _write_json(evidence_dir / "test-policy-summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument(
        "--profile",
        choices=("baseline", "python", "node", "powershell", "critical-ml"),
        required=True,
    )
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--coverage-xml", type=pathlib.Path, required=True)
    parser.add_argument("--coverage-json", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-site", type=pathlib.Path, required=True)
    parser.add_argument("--target-site", type=pathlib.Path)
    parser.add_argument("--protected-base-manifest", type=pathlib.Path)
    parser.add_argument("--protected-pytest-config", type=pathlib.Path)
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    run_policy(
        root=pathlib.Path.cwd(),
        base_sha=arguments.base_sha,
        profile=arguments.profile,
        evidence_dir=arguments.evidence_dir,
        coverage_xml=arguments.coverage_xml,
        coverage_json=arguments.coverage_json,
        trusted_site=arguments.trusted_site,
        target_site=arguments.target_site,
        protected_base_manifest=arguments.protected_base_manifest,
        protected_pytest_config=arguments.protected_pytest_config,
    )


if __name__ == "__main__":
    main()
