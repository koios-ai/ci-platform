"""Select bounded affected tests from the protected-base declarative policy."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from test_policy import (
    load_policy_from_base,
    validate_profile_policy,
)

SAFE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
MAX_CHANGED_PATHS = 5_000
MAX_TEST_CANDIDATES = 5_000
MAX_TEST_BYTES = 1_000_000
MAX_FAST_TESTS = 128
CRITICAL_MARKERS = (
    "src/features/",
    "src/inference/",
    "src/training/",
    "src/validation/",
    "src/orchestrator/",
    "src/deployment/",
    "leakage",
    "lineage",
    "schema",
    "model_registry",
    "prediction",
)
CRITICAL_EXACT_PATHS = {
    ".bandit",
    ".coderabbit.yaml",
    ".deepsource.toml",
    ".github/ci-platform-test-policy.json",
    ".mypy.ini",
    ".ruff.toml",
    ".semgrep.yml",
    ".semgrep.yaml",
    "bandit.yaml",
    "bandit.yml",
    "mypy.ini",
    "pyproject.toml",
    "pytest.ini",
    "quality_debt.yml",
    "ruff.toml",
    "scripts/install_hooks.py",
    "scripts/sync_venvs.sh",
    "setup.cfg",
    "tools/check_coverage_ratchet.py",
    "tools/check_data_quality_contract.py",
    "tools/check_docstring_contracts.py",
    "tools/check_module_coverage.py",
    "tools/check_rebuild_contract.py",
    "tools/check_schema_contract.py",
    "tools/normalize_coverage_paths.py",
    "tox.ini",
}
CRITICAL_PREFIXES = (
    ".github/actions/",
    ".github/ci/",
    ".github/workflows/",
    "tests/",
)


def _safe_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 240
        or not SAFE_PATH.fullmatch(value)
        or value.startswith("-")
        or "\\" in value
    ):
        raise ValueError(f"changed-file list contains an unsafe path: {value!r}")
    parsed = pathlib.PurePosixPath(value)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError(f"changed-file list contains an unsafe path: {value!r}")
    return parsed.as_posix()


def load_changed_paths(path: pathlib.Path) -> list[str]:
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("changed-file evidence is missing or oversized")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("changed-file evidence is not valid UTF-8 JSON") from error
    if not isinstance(value, list) or len(value) > MAX_CHANGED_PATHS:
        raise ValueError("changed-file evidence is not a bounded list")
    parsed = [_safe_path(item) for item in value]
    if parsed != sorted(set(parsed)):
        raise ValueError("changed-file evidence is not sorted and unique")
    return parsed


def classify_profile(paths: Iterable[str]) -> str:
    lowered = [path.lower() for path in paths]
    if any(
        path in CRITICAL_EXACT_PATHS
        or path.startswith(CRITICAL_PREFIXES)
        or pathlib.PurePosixPath(path).name.startswith(("constraints", "requirements"))
        or any(marker in path for marker in CRITICAL_MARKERS)
        for path in lowered
    ):
        return "critical-ml"
    if any(path.endswith(".py") for path in lowered):
        return "python"
    return "baseline"


def _under_roots(path: str, roots: Sequence[str]) -> bool:
    candidate = pathlib.PurePosixPath(path)
    return any(
        candidate == pathlib.PurePosixPath(root) or pathlib.PurePosixPath(root) in candidate.parents for root in roots
    )


def _is_test_like(path: str) -> bool:
    parsed = pathlib.PurePosixPath(path)
    return parsed.name.startswith("test_") or parsed.name.endswith("_test.py") or "tests" in parsed.parts


def _changed_module_candidates(path: str) -> set[tuple[str, str]]:
    parsed = pathlib.PurePosixPath(path)
    if parsed.suffix != ".py":
        return set()
    parts = list(parsed.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return set()
    variants = [parts]
    if parts[0] in {"lib", "src"} and len(parts) > 1:
        variants.append(parts[1:])
    return {(".".join(value), value[-1]) for value in variants if value and all(part.isidentifier() for part in value)}


def _imports_changed_module(tree: ast.AST, modules: set[tuple[str, str]]) -> bool:
    module_names = {module for module, _ in modules}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name in module_names for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and isinstance(node.module, str):
            if node.module in module_names:
                return True
            if any(f"{node.module}.{alias.name}" in module_names for alias in node.names):
                return True
    return False


def _test_candidates(
    policy: Mapping[str, Any],
    *,
    root: pathlib.Path,
) -> list[tuple[str, pathlib.Path]]:
    root = root.resolve()
    observed: dict[str, pathlib.Path] = {}
    for declared_root in policy["test_roots"]:
        test_root = (root / pathlib.PurePosixPath(declared_root)).resolve()
        try:
            test_root.relative_to(root)
        except ValueError as error:
            raise ValueError("protected test root resolves outside repository") from error
        for candidate in sorted(test_root.rglob("*.py")):
            resolved = candidate.resolve()
            try:
                relative = resolved.relative_to(root)
            except ValueError as error:
                raise ValueError("test candidate resolves outside repository") from error
            if not resolved.is_file():
                continue
            posix = relative.as_posix()
            if _is_test_like(posix):
                if resolved.stat().st_size > MAX_TEST_BYTES:
                    raise ValueError(f"test candidate exceeds the size limit: {posix}")
                observed[posix] = resolved
            if len(observed) > MAX_TEST_CANDIDATES:
                raise ValueError("test candidate scan exceeds the bounded maximum")
    return sorted(observed.items())


def select_fast_tests(
    policy: Mapping[str, Any],
    *,
    root: pathlib.Path,
    changed_paths: Sequence[str],
) -> list[str]:
    """Return only explicit, changed, or statically direct affected tests."""
    roots = policy["test_roots"]
    changed_python = [path for path in changed_paths if path.endswith(".py")]
    escaped_tests = [path for path in changed_python if _is_test_like(path) and not _under_roots(path, roots)]
    if escaped_tests:
        raise ValueError("changed test path is outside protected test roots: " + ", ".join(sorted(escaped_tests)))

    selected = {
        path
        for path in changed_python
        if _is_test_like(path) and _under_roots(path, roots) and (root / pathlib.PurePosixPath(path)).is_file()
    }
    changed_sources = [
        path
        for path in changed_python
        if not _under_roots(path, roots) and (root / pathlib.PurePosixPath(path)).is_file()
    ]
    if any(any(marker in path.lower() for marker in CRITICAL_MARKERS) for path in changed_sources):
        selected.update(
            path for category in sorted(policy["critical_tests"]) for path in policy["critical_tests"][category]
        )

    modules = {module for changed in changed_sources for module in _changed_module_candidates(changed)}
    stems = {stem for _, stem in modules}
    for relative, candidate in _test_candidates(policy, root=root):
        if relative in selected:
            continue
        if candidate.stem.removeprefix("test_") in stems:
            selected.add(relative)
            continue
        if modules:
            try:
                tree = ast.parse(candidate.read_text(encoding="utf-8"), filename=relative)
            except (SyntaxError, UnicodeDecodeError) as error:
                raise ValueError(f"test candidate is not valid UTF-8 Python: {relative}") from error
            if _imports_changed_module(tree, modules):
                selected.add(relative)

    if len(selected) > MAX_FAST_TESTS:
        raise ValueError("affected test selection exceeds the bounded maximum")
    return sorted(selected)


def selection_digest(paths: Sequence[str]) -> str:
    return hashlib.sha256("".join(f"{path}\n" for path in paths).encode("utf-8")).hexdigest()


def build_selection(
    *,
    root: pathlib.Path,
    base_sha: str,
    changed_files_path: pathlib.Path,
) -> dict[str, Any]:
    changed = load_changed_paths(changed_files_path)
    policy, policy_digest = load_policy_from_base(root, base_sha)
    profile = classify_profile(changed)
    validate_profile_policy(policy, profile)
    selected = select_fast_tests(policy, root=root, changed_paths=changed)
    return {
        "schema_version": 1,
        "base_sha": base_sha,
        "profile": profile,
        "policy_digest": policy_digest,
        "changed_files_digest": selection_digest(changed),
        "selected_tests_digest": selection_digest(selected),
        "selected_tests": selected,
    }


def _write_json(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--changed-files", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_args()
    selection = build_selection(
        root=arguments.root,
        base_sha=arguments.base_sha,
        changed_files_path=arguments.changed_files,
    )
    _write_json(arguments.output, selection)
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if not github_output:
        raise ValueError("GITHUB_OUTPUT is unavailable")
    with open(github_output, "a", encoding="utf-8") as output:
        output.write(f"has_tests={str(bool(selection['selected_tests'])).lower()}\n")
        output.write(f"profile={selection['profile']}\n")
        output.write(f"selected_tests_digest={selection['selected_tests_digest']}\n")


if __name__ == "__main__":
    main()
