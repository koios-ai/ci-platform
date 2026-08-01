"""Run only the protected-base bounded affected-test selection."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
from collections.abc import Mapping
from typing import Any

from fast_test_selection import build_selection
from run_test_policy import _junit_counts
from test_policy import (
    build_fast_pytest_command,
    load_policy_from_base,
    pytest_subprocess_environment,
    remove_pytest_basetemp,
)

SELECTION_KEYS = {
    "base_sha",
    "changed_files_digest",
    "policy_digest",
    "profile",
    "schema_version",
    "selected_tests",
    "selected_tests_digest",
}


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate fast-test selection key: {key}")
        value[key] = item
    return value


def _load_selection(path: pathlib.Path) -> Mapping[str, Any]:
    if not path.is_file() or path.stat().st_size > 256_000:
        raise ValueError("fast-test selection evidence is missing or oversized")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("fast-test selection evidence is malformed") from error
    if not isinstance(value, Mapping) or set(value) != SELECTION_KEYS:
        raise ValueError("fast-test selection evidence has an open schema")
    return value


def run_fast_tests(
    *,
    root: pathlib.Path,
    base_sha: str,
    changed_files_path: pathlib.Path,
    selection_path: pathlib.Path,
    evidence_path: pathlib.Path,
    trusted_site: pathlib.Path,
    target_site: pathlib.Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    observed = _load_selection(selection_path)
    expected = build_selection(
        root=root,
        base_sha=base_sha,
        changed_files_path=changed_files_path,
    )
    if observed != expected:
        raise ValueError("fast-test selection changed between selection and execution")
    selected = expected["selected_tests"]
    if not isinstance(selected, list) or not selected:
        raise ValueError("fast-test runner received no selected tests")
    policy, policy_digest = load_policy_from_base(root, base_sha)
    if policy_digest != expected["policy_digest"]:
        raise ValueError("protected test policy digest changed")

    evidence_path = evidence_path.resolve()
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    junit_path = evidence_path.parent / "fast-pytest-junit.xml"
    command = build_fast_pytest_command(
        policy,
        selected_tests=selected,
        junit_path=junit_path,
        trusted_site=trusted_site,
        target_root=root,
        target_site=target_site,
    )
    try:
        subprocess.run(
            command,
            cwd=root,
            check=True,
            timeout=600,
            env=pytest_subprocess_environment(),
        )
    finally:
        remove_pytest_basetemp(junit_path, "fast")
    counts = _junit_counts(junit_path)
    summary = {
        "base_sha": base_sha,
        "command": command,
        "policy_digest": policy_digest,
        "profile": expected["profile"],
        "selected_tests": selected,
        "selected_tests_digest": expected["selected_tests_digest"],
        "status": "passed",
        "test_counts": counts,
        "unexpected_skip_policy": policy["unexpected_skip_policy"],
    }
    evidence_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--changed-files", type=pathlib.Path, required=True)
    parser.add_argument("--selection", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-site", type=pathlib.Path, required=True)
    parser.add_argument("--target-site", type=pathlib.Path)
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    run_fast_tests(
        root=arguments.root,
        base_sha=arguments.base_sha,
        changed_files_path=arguments.changed_files,
        selection_path=arguments.selection,
        evidence_path=arguments.evidence,
        trusted_site=arguments.trusted_site,
        target_site=arguments.target_site,
    )


if __name__ == "__main__":
    main()
