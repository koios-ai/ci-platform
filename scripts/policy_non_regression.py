"""Reject consumer CI policy/config changes that weaken the protected base."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib
from collections.abc import Mapping
from typing import Any

import yaml
from evaluate_coverage import CoveragePolicy, load_policy_bytes
from test_policy import (
    canonical_policy_digest,
    parse_policy_bytes,
    validate_test_policy,
)

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
QUALITY_DEBT_PATH = "quality_debt.yml"
TEST_POLICY_PATH = ".github/ci-platform-test-policy.json"
MAX_POLICY_BYTES = 256 * 1024
EXACT_PROTECTED_CONFIGS = frozenset(
    {
        ".bandit",
        ".coderabbit.yaml",
        ".deepsource.toml",
        ".mypy.ini",
        ".ruff.toml",
        ".semgrep.yml",
        ".semgrep.yaml",
        "bandit.yaml",
        "bandit.yml",
        "mypy.ini",
        "pytest.ini",
        "ruff.toml",
        "scripts/install_hooks.py",
        "scripts/sync_venvs.sh",
        "setup.cfg",
        "tox.ini",
    }
)
PYPROJECT_PROTECTED_TOOLS = frozenset(
    {
        "bandit",
        "coverage",
        "mypy",
        "pytest",
        "pytest.ini_options",
        "ruff",
        "semgrep",
    }
)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_yaml_mapping(raw: bytes, name: str) -> dict[str, Any]:
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError(f"{name} exceeds the policy size limit")
    try:
        decoded = raw.decode("utf-8")
        value = yaml.load(decoded, Loader=UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError(f"{name} is not valid UTF-8 YAML") from error
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _git_blob(
    root: pathlib.Path,
    sha: str,
    relative: str,
    *,
    required: bool,
) -> bytes | None:
    if not FULL_SHA.fullmatch(sha):
        raise ValueError("protected-base SHA is malformed")
    result = subprocess.run(
        ["git", "show", f"{sha}:{relative}"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        if len(result.stdout) > MAX_POLICY_BYTES:
            raise ValueError(f"protected {relative} exceeds the policy size limit")
        return result.stdout
    if required:
        raise ValueError(f"protected base has no readable {relative}")
    return None


def _head_blob(
    root: pathlib.Path,
    relative: str,
    *,
    required: bool,
) -> bytes | None:
    path = root / pathlib.PurePosixPath(relative)
    if not path.is_file():
        if required:
            raise ValueError(f"pull-request head has no {relative}")
        return None
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError(f"head {relative} exceeds the policy size limit")
    return raw


def _set_non_regression(
    base: list[str],
    head: list[str],
    *,
    field: str,
    reversed_strength: bool = False,
) -> None:
    base_set = set(base)
    head_set = set(head)
    removed = sorted((head_set - base_set) if reversed_strength else (base_set - head_set))
    if removed:
        direction = "added weakening entries" if reversed_strength else "removed protected entries"
        raise ValueError(f"{field} {direction}: {removed}")


def validate_test_policy_non_regression(
    base_raw: bytes,
    head_raw: bytes,
    *,
    root: pathlib.Path,
) -> tuple[str, str]:
    base = validate_test_policy(parse_policy_bytes(base_raw), root=root)
    head = validate_test_policy(parse_policy_bytes(head_raw), root=root)
    _set_non_regression(base["test_roots"], head["test_roots"], field="test_roots")
    _set_non_regression(
        base["coverage_sources"],
        head["coverage_sources"],
        field="coverage_sources",
    )
    _set_non_regression(
        base["marker_exclusions"],
        head["marker_exclusions"],
        field="marker_exclusions",
        reversed_strength=True,
    )
    _set_non_regression(
        base["registered_markers"],
        head["registered_markers"],
        field="registered_markers",
    )
    _set_non_regression(
        base["disabled_plugins"],
        head["disabled_plugins"],
        field="disabled_plugins",
        reversed_strength=True,
    )
    _set_non_regression(
        base["protected_support_files"],
        head["protected_support_files"],
        field="protected_support_files",
    )
    for category in sorted(base["critical_tests"]):
        _set_non_regression(
            base["critical_tests"][category],
            head["critical_tests"][category],
            field=f"critical_tests.{category}",
        )
    return canonical_policy_digest(base), canonical_policy_digest(head)


def _require_at_least(base: float, head: float, field: str) -> None:
    if head + 1e-9 < base:
        raise ValueError(f"{field} decreased from {base:g} to {head:g}")


def validate_coverage_non_regression(
    base: CoveragePolicy,
    head: CoveragePolicy,
) -> None:
    _require_at_least(base.global_floor, head.global_floor, "coverage.global_floor")
    _require_at_least(base.diff_floor, head.diff_floor, "coverage.diff_floor")
    _require_at_least(
        base.critical_patch_floor,
        head.critical_patch_floor,
        "coverage.critical_patch.target",
    )
    _set_non_regression(
        list(base.critical_paths),
        list(head.critical_paths),
        field="coverage.critical_patch.paths",
    )
    missing_groups = sorted(set(base.path_groups) - set(head.path_groups))
    if missing_groups:
        raise ValueError(f"coverage.path_groups removed protected entries: {missing_groups}")
    for prefix, base_group in base.path_groups.items():
        head_group = head.path_groups[prefix]
        _require_at_least(
            base_group.floor,
            head_group.floor,
            f"coverage.path_groups.{prefix}.floor",
        )
        _require_at_least(
            base_group.target,
            head_group.target,
            f"coverage.path_groups.{prefix}.target",
        )


def validate_quality_debt_non_regression(
    base_raw: bytes,
    head_raw: bytes,
) -> tuple[str, str]:
    base_mapping = _load_yaml_mapping(base_raw, "protected quality_debt.yml")
    head_mapping = _load_yaml_mapping(head_raw, "head quality_debt.yml")
    validate_coverage_non_regression(
        load_policy_bytes(base_raw),
        load_policy_bytes(head_raw),
    )
    base_data_quality = base_mapping.get("data_quality")
    head_data_quality = head_mapping.get("data_quality")
    if (
        isinstance(base_data_quality, Mapping)
        and base_data_quality.get("pull_request_fixture_required") is True
        and (
            not isinstance(head_data_quality, Mapping)
            or head_data_quality.get("pull_request_fixture_required") is not True
        )
    ):
        raise ValueError("data_quality.pull_request_fixture_required was weakened")
    if "docstrings" in base_mapping and "docstrings" not in head_mapping:
        raise ValueError("docstrings policy was removed")
    return hashlib.sha256(base_raw).hexdigest(), hashlib.sha256(head_raw).hexdigest()


def _protected_pyproject_tools(raw: bytes | None) -> Mapping[str, Any] | None:
    if raw is None:
        return None
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("pyproject.toml is not valid UTF-8 TOML") from error
    tool = value.get("tool", {})
    if not isinstance(tool, Mapping):
        raise ValueError("pyproject.toml tool section is malformed")
    return {key: tool[key] for key in sorted(PYPROJECT_PROTECTED_TOOLS) if key in tool}


def validate_protected_configs(
    root: pathlib.Path,
    base_sha: str,
) -> list[str]:
    checked: list[str] = []
    for relative in sorted(EXACT_PROTECTED_CONFIGS):
        base = _git_blob(root, base_sha, relative, required=False)
        head = _head_blob(root, relative, required=False)
        if base != head:
            raise ValueError(
                f"protected CI/tool configuration changed without an audited platform migration: {relative}"
            )
        if base is not None:
            checked.append(relative)
    base_pyproject = _protected_pyproject_tools(_git_blob(root, base_sha, "pyproject.toml", required=False))
    head_pyproject = _protected_pyproject_tools(_head_blob(root, "pyproject.toml", required=False))
    if base_pyproject != head_pyproject:
        raise ValueError("protected pyproject.toml tool configuration changed")
    if base_pyproject is not None:
        checked.append("pyproject.toml:[tool]")
    return checked


def validate_repository_policy(
    *,
    root: pathlib.Path,
    base_sha: str,
    output: pathlib.Path,
) -> dict[str, Any]:
    root = root.resolve()
    base_test = _git_blob(root, base_sha, TEST_POLICY_PATH, required=True)
    head_test = _head_blob(root, TEST_POLICY_PATH, required=True)
    assert base_test is not None and head_test is not None
    base_test_digest, head_test_digest = validate_test_policy_non_regression(
        base_test,
        head_test,
        root=root,
    )

    base_quality = _git_blob(root, base_sha, QUALITY_DEBT_PATH, required=False)
    head_quality = _head_blob(root, QUALITY_DEBT_PATH, required=False)
    if base_quality is None:
        if head_quality is not None:
            load_policy_bytes(head_quality)
        base_quality_digest = hashlib.sha256(b"absent\n").hexdigest()
        head_quality_digest = hashlib.sha256(head_quality if head_quality is not None else b"absent\n").hexdigest()
    else:
        if head_quality is None:
            raise ValueError("quality_debt.yml was removed")
        base_quality_digest, head_quality_digest = validate_quality_debt_non_regression(
            base_quality,
            head_quality,
        )

    summary = {
        "base_sha": base_sha,
        "base_test_policy_digest": base_test_digest,
        "head_test_policy_digest": head_test_digest,
        "base_quality_debt_digest": base_quality_digest,
        "head_quality_debt_digest": head_quality_digest,
        "protected_configs": validate_protected_configs(root, base_sha),
        "status": "passed",
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    validate_repository_policy(
        root=pathlib.Path.cwd(),
        base_sha=arguments.base_sha,
        output=arguments.output,
    )


if __name__ == "__main__":
    main()
