"""Closed parser and command builder for consumer pytest/coverage policy."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

POLICY_PATH = ".github/ci-platform-test-policy.json"
POLICY_LIMIT = 64 * 1024
PROTECTED_BASE_MANIFEST_LIMIT = 256 * 1024
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
POLICY_KEYS = {
    "coverage_sources",
    "critical_tests",
    "disabled_plugins",
    "marker_exclusions",
    "protected_support_files",
    "registered_markers",
    "test_roots",
    "unexpected_skip_policy",
    "version",
}
CRITICAL_CATEGORIES = {"leakage", "lineage", "model", "parity", "schema"}
MARKER_EXCLUSION_ALLOWLIST = {
    "external",
    "gpu",
    "requires_credentials",
    "requires_network",
    "resource_heavy",
    "slow",
}
REGISTERED_MARKER_ALLOWLIST = MARKER_EXCLUSION_ALLOWLIST | {
    "cli",
    "cli_quick",
    "cli_subprocess",
    "critical",
    "integration",
    "leakage",
    "smoke",
    "unit",
}
DISABLED_PLUGIN_ALLOWLIST = {"benchmark"}
PYTEST_BASETEMP_NAME = re.compile(r"^ci-platform-pytest-(?:critical|fast|full)-[0-9a-f]{24}$")
PYTEST_BASETEMP_MAX_ENTRIES = 100_000
PYTEST_BASETEMP_MAX_DEPTH = 32
PYTEST_CONFIG_DIRECTORY_NAME = re.compile(r"^\.ci-platform-pytest-config-[0-9a-f]{24}$")
PYTEST_CONFIG_LIMIT = 64 * 1024
CONFTEST_SCAN_MAX_ENTRIES = 100_000
CONFTEST_SCAN_MAX_DEPTH = 32
PYTEST_ENTRYPOINT = pathlib.Path(__file__).with_name("run_pytest_isolated.py").resolve()
PYTEST_CONFIG = pathlib.Path(__file__).resolve().parents[1] / "contract" / "pytest-v1.ini"
COVERAGE_CONFIG = pathlib.Path(__file__).resolve().parents[1] / "contract" / "coverage-v1.ini"


def _pytest_prefix(
    *,
    basetemp: pathlib.Path,
    trusted_site: pathlib.Path,
    target_root: pathlib.Path,
    target_site: pathlib.Path | None,
    registered_markers: Sequence[str],
    protected_pytest_config: pathlib.Path | None = None,
) -> list[str]:
    trusted_site = trusted_site.resolve()
    if not trusted_site.is_dir():
        raise ValueError("trusted pytest site-packages path is unavailable")
    target_root = target_root.resolve()
    if not target_root.is_dir():
        raise ValueError("target pytest root is unavailable")
    prefix = [
        sys.executable,
        "-I",
        "-S",
        str(PYTEST_ENTRYPOINT),
        "--trusted-site",
        str(trusted_site),
        "--target-root",
        str(target_root),
    ]
    if target_site is not None:
        prefix.extend(("--target-site", str(target_site.resolve())))
    for marker in registered_markers:
        if marker not in REGISTERED_MARKER_ALLOWLIST:
            raise ValueError(f"unapproved registered marker: {marker}")
        prefix.extend(("--registered-marker", marker))
    if not PYTEST_CONFIG.is_file() or not COVERAGE_CONFIG.is_file():
        raise ValueError("immutable pytest or coverage config is unavailable")
    if protected_pytest_config is None:
        config_path = pytest_config_path(basetemp, target_root)
        config_argument = pytest_runtime_argument_path(config_path, target_root)
    else:
        config_path = validate_external_pytest_config(protected_pytest_config)
        config_argument = str(config_path)
        prefix.extend(("--protected-config", config_argument))
    prefix.append("--")
    prefix.extend(
        (
            "--rootdir",
            ".",
            "--confcutdir",
            ".",
            "-c",
            config_argument,
            f"--basetemp={pytest_runtime_argument_path(basetemp, target_root)}",
        )
    )
    return prefix


def pytest_runtime_argument_path(path: pathlib.Path, target_root: pathlib.Path) -> str:
    """Express a trusted runtime path without a Windows drive-colon pytest can parse as a node ID."""
    try:
        relative = pathlib.Path(os.path.relpath(path.resolve(), target_root.resolve()))
    except ValueError as error:
        raise ValueError("pytest runtime path is on a different filesystem root") from error
    if relative.is_absolute() or str(relative) in {"", "."}:
        raise ValueError("pytest runtime path did not become a bounded relative argument")
    return str(relative)


def pytest_basetemp_path(junit_path: pathlib.Path, purpose: str) -> pathlib.Path:
    """Return a per-target temporary root so nested pytest runs never share global state."""
    if purpose not in {"critical", "fast", "full"}:
        raise ValueError(f"unsupported pytest basetemp purpose: {purpose}")
    identity = f"{junit_path.resolve()}\0{purpose}".encode()
    digest = hashlib.sha256(identity).hexdigest()[:24]
    return trusted_pytest_temp_root() / f"ci-platform-pytest-{purpose}-{digest}"


def _is_reparse_point(metadata: object) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def trusted_pytest_temp_root() -> pathlib.Path:
    """Resolve the exact OS temporary root only when it is a real directory."""
    candidate = pathlib.Path(tempfile.gettempdir())
    metadata = candidate.lstat()
    if candidate.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("OS temporary root is not a trusted regular directory")
    return candidate.resolve(strict=True)


def _validated_pytest_basetemp(path: pathlib.Path) -> pathlib.Path:
    trusted_root = trusted_pytest_temp_root()
    candidate = pathlib.Path(os.path.abspath(path))
    if candidate.parent != trusted_root or not PYTEST_BASETEMP_NAME.fullmatch(candidate.name):
        raise ValueError("pytest basetemp escapes the exact trusted OS temporary root")
    return candidate


def remove_pytest_basetemp_path(path: pathlib.Path) -> None:
    """Delete one exact platform basetemp without traversing links or reparse points."""
    basetemp = _validated_pytest_basetemp(path)
    try:
        metadata = basetemp.lstat()
    except FileNotFoundError:
        return
    if basetemp.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"pytest basetemp is not a regular directory: {basetemp}")
    if basetemp.resolve(strict=True) != basetemp:
        raise ValueError("pytest basetemp resolution changed")

    pending: list[tuple[pathlib.Path, bool, int]] = [(basetemp, False, 0)]
    entries = 0
    while pending:
        current, visited, depth = pending.pop()
        if depth > PYTEST_BASETEMP_MAX_DEPTH:
            raise ValueError("pytest basetemp exceeds the cleanup depth limit")
        current_metadata = current.lstat()
        if current.is_symlink() or _is_reparse_point(current_metadata):
            raise ValueError(f"pytest basetemp contains a link or reparse point: {current}")
        if stat.S_ISDIR(current_metadata.st_mode):
            if visited:
                current.rmdir()
                continue
            pending.append((current, True, depth))
            children = list(current.iterdir())
            entries += len(children)
            if entries > PYTEST_BASETEMP_MAX_ENTRIES:
                raise ValueError("pytest basetemp exceeds the cleanup entry limit")
            pending.extend((child, False, depth + 1) for child in children)
        elif stat.S_ISREG(current_metadata.st_mode):
            current.unlink()
        else:
            raise ValueError(f"pytest basetemp contains an unsupported filesystem object: {current}")


def remove_pytest_basetemp(junit_path: pathlib.Path, purpose: str) -> None:
    """Remove only the fixed temporary root created for one isolated pytest phase."""
    remove_pytest_basetemp_path(pytest_basetemp_path(junit_path, purpose))


def _immutable_pytest_ini_bytes() -> bytes:
    try:
        metadata = PYTEST_CONFIG.lstat()
    except OSError as error:
        raise ValueError("immutable pytest config is unavailable") from error
    if PYTEST_CONFIG.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("immutable pytest config is not a regular file")
    raw = PYTEST_CONFIG.read_bytes()
    if not raw or len(raw) > PYTEST_CONFIG_LIMIT:
        raise ValueError("immutable pytest config is empty or oversized")
    return raw


def validate_external_pytest_config(path: pathlib.Path) -> pathlib.Path:
    """Accept only the platform-owned immutable pytest config outside the target checkout."""
    candidate = pathlib.Path(os.path.abspath(path))
    expected = pathlib.Path(os.path.abspath(PYTEST_CONFIG))
    if candidate != expected:
        raise ValueError("external pytest config is not the exact platform-owned config")
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError("external pytest config is unavailable") from error
    if candidate.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("external pytest config is not a regular file")
    if candidate.resolve(strict=True) != expected.resolve(strict=True):
        raise ValueError("external pytest config resolution changed")
    if candidate.read_bytes() != _immutable_pytest_ini_bytes():
        raise ValueError("external pytest config bytes differ from the platform config")
    return candidate


def _trusted_target_root(target_root: pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(os.path.abspath(target_root))
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError("target pytest root is unavailable") from error
    if candidate.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("target pytest root is not a regular directory")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate:
        raise ValueError("target pytest root resolution changed")
    return candidate


def pytest_config_path(basetemp: pathlib.Path, target_root: pathlib.Path) -> pathlib.Path:
    """Return the exact checkout-local path used for one immutable pytest config."""
    root = _trusted_target_root(target_root)
    validated_basetemp = _validated_pytest_basetemp(basetemp)
    config_digest = hashlib.sha256(_immutable_pytest_ini_bytes()).hexdigest()
    identity = f"{validated_basetemp}\0{config_digest}".encode()
    digest = hashlib.sha256(identity).hexdigest()[:24]
    return root / f".ci-platform-pytest-config-{digest}" / "pytest.ini"


def _validated_pytest_config_directory(
    directory: pathlib.Path,
    target_root: pathlib.Path,
) -> pathlib.Path:
    root = _trusted_target_root(target_root)
    candidate = pathlib.Path(os.path.abspath(directory))
    if candidate.parent != root or not PYTEST_CONFIG_DIRECTORY_NAME.fullmatch(candidate.name):
        raise ValueError("pytest config directory escapes the exact target root")
    return candidate


def stage_pytest_config(basetemp: pathlib.Path, target_root: pathlib.Path) -> pathlib.Path:
    """Atomically stage one trusted config below the target so Windows pytest keeps the right root."""
    config_path = pytest_config_path(basetemp, target_root)
    directory = _validated_pytest_config_directory(config_path.parent, target_root)
    directory.mkdir(mode=0o700)
    metadata = directory.lstat()
    if directory.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("pytest config directory is not a regular directory")
    if directory.resolve(strict=True) != directory:
        raise ValueError("pytest config directory resolution changed")
    try:
        with config_path.open("xb") as handle:
            handle.write(_immutable_pytest_ini_bytes())
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        directory.rmdir()
        raise
    config_path.chmod(stat.S_IREAD)
    config_metadata = config_path.lstat()
    if (
        config_path.is_symlink()
        or _is_reparse_point(config_metadata)
        or not stat.S_ISREG(config_metadata.st_mode)
        or config_metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("staged pytest config is not a regular file")
    return config_path


def remove_pytest_config_path(
    directory: pathlib.Path,
    target_root: pathlib.Path,
    *,
    required: bool = False,
) -> None:
    """Remove only one exact platform-owned config file and its direct parent."""
    validated = _validated_pytest_config_directory(directory, target_root)
    try:
        metadata = validated.lstat()
    except FileNotFoundError:
        if required:
            raise ValueError("staged pytest config directory disappeared during execution") from None
        return
    if validated.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("pytest config directory is not a regular directory")
    if validated.resolve(strict=True) != validated:
        raise ValueError("pytest config directory resolution changed")
    entries = list(validated.iterdir())
    if len(entries) != 1 or entries[0].name != "pytest.ini":
        raise ValueError("pytest config directory contains unexpected entries")
    config_path = entries[0]
    config_metadata = config_path.lstat()
    if config_path.is_symlink() or _is_reparse_point(config_metadata) or not stat.S_ISREG(config_metadata.st_mode):
        raise ValueError("staged pytest config is not a regular file")
    changed_mode = bool(config_metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        changed_bytes = config_path.read_bytes() != _immutable_pytest_ini_bytes()
    except OSError:
        changed_bytes = True
    config_path.chmod(stat.S_IREAD | stat.S_IWRITE)
    config_path.unlink()
    validated.rmdir()
    if changed_bytes or changed_mode:
        raise ValueError("staged pytest config bytes or mode changed during execution")


def remove_pytest_config(
    basetemp: pathlib.Path,
    target_root: pathlib.Path,
    *,
    required: bool = False,
) -> None:
    """Remove the exact immutable config directory derived for one isolated run."""
    remove_pytest_config_path(
        pytest_config_path(basetemp, target_root).parent,
        target_root,
        required=required,
    )


def _cache_provider_arguments() -> list[str]:
    """Keep generated policy runs from writing a checkout-local pytest cache."""
    return ["-p", "no:cacheprovider"]


def pytest_subprocess_environment() -> dict[str, str]:
    """Strip caller pytest controls; the isolated entrypoint sets its own closed state."""
    environment = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTEST_PLUGINS"):
        environment.pop(name, None)
    return environment


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_policy_bytes(raw: bytes) -> Mapping[str, Any]:
    if not raw or len(raw) > POLICY_LIMIT:
        raise ValueError("test policy is empty or exceeds the size limit")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("test policy is not valid UTF-8 JSON") from error
    if not isinstance(value, Mapping):
        raise ValueError("test policy root must be an object")
    return value


def _closed_string_list(
    value: Any,
    *,
    field: str,
    maximum: int,
    allowlist: set[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field} must be a bounded list")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field} entries must be non-empty strings")
    parsed = list(value)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"{field} contains duplicate entries")
    if allowlist is not None:
        unexpected = sorted(set(parsed) - allowlist)
        if unexpected:
            label = "marker" if field == "marker_exclusions" else "plugin"
            raise ValueError(f"unapproved {label} selector: {unexpected}")
    return parsed


def _safe_repository_path(value: str, field: str) -> str:
    if len(value) > 240 or not SAFE_PATH.fullmatch(value) or value.startswith("-") or "\\" in value:
        raise ValueError(f"{field} contains an unsafe repository path: {value!r}")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field} contains an unsafe repository path: {value!r}")
    return path.as_posix()


def _repository_path_list(
    value: Any,
    *,
    field: str,
    maximum: int,
    suffix: str | None = None,
) -> list[str]:
    parsed = _closed_string_list(value, field=field, maximum=maximum)
    paths = [_safe_repository_path(item, field) for item in parsed]
    if suffix is not None and any(not path.endswith(suffix) for path in paths):
        raise ValueError(f"{field} entries must end with {suffix}")
    return paths


def _path_under_roots(path: str, roots: Sequence[str]) -> bool:
    candidate = pathlib.PurePosixPath(path)
    return any(
        candidate == pathlib.PurePosixPath(root) or pathlib.PurePosixPath(root) in candidate.parents for root in roots
    )


def validate_test_policy(
    value: Mapping[str, Any],
    *,
    root: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Validate the exact v1 schema and optionally bind paths to a checkout."""
    if set(value) != POLICY_KEYS:
        raise ValueError(f"test policy keys differ from the closed v1 schema: {sorted(set(value) ^ POLICY_KEYS)}")
    if value.get("version") != 1:
        raise ValueError("test policy version must be exactly 1")
    if value.get("unexpected_skip_policy") != "fail":
        raise ValueError("unexpected_skip_policy must be fail")

    test_roots = _repository_path_list(
        value.get("test_roots"),
        field="test_roots path",
        maximum=8,
    )
    markers = _closed_string_list(
        value.get("marker_exclusions"),
        field="marker_exclusions",
        maximum=8,
        allowlist=MARKER_EXCLUSION_ALLOWLIST,
    )
    registered_markers = _closed_string_list(
        value.get("registered_markers"),
        field="registered_markers",
        maximum=16,
        allowlist=REGISTERED_MARKER_ALLOWLIST,
    )
    missing_marker_registrations = sorted(set(markers) - set(registered_markers))
    if missing_marker_registrations:
        raise ValueError(
            "marker_exclusions must be present in registered_markers: " + ", ".join(missing_marker_registrations)
        )
    plugins = _closed_string_list(
        value.get("disabled_plugins"),
        field="disabled_plugins",
        maximum=1,
        allowlist=DISABLED_PLUGIN_ALLOWLIST,
    )
    coverage_sources = _repository_path_list(
        value.get("coverage_sources"),
        field="coverage_sources",
        maximum=32,
    )
    protected_support_files = _repository_path_list(
        value.get("protected_support_files"),
        field="protected_support_files",
        maximum=64,
        suffix=".py",
    )
    support_outside_roots = [path for path in protected_support_files if not _path_under_roots(path, test_roots)]
    if support_outside_roots:
        raise ValueError(f"protected_support_files paths are outside test_roots: {support_outside_roots}")

    critical_value = value.get("critical_tests")
    if not isinstance(critical_value, Mapping) or set(critical_value) != CRITICAL_CATEGORIES:
        raise ValueError("critical_tests must contain only leakage, lineage, model, schema, and parity")
    critical_tests = {
        category: _repository_path_list(
            critical_value.get(category),
            field=f"critical_tests.{category}",
            maximum=64,
            suffix=".py",
        )
        for category in sorted(CRITICAL_CATEGORIES)
    }
    all_critical = [path for category in sorted(critical_tests) for path in critical_tests[category]]
    if len(set(all_critical)) != len(all_critical):
        raise ValueError("critical_tests contains a path in multiple categories")
    outside_roots = [path for path in all_critical if not _path_under_roots(path, test_roots)]
    if outside_roots:
        raise ValueError(f"critical_tests paths are outside test_roots: {outside_roots}")

    if root is not None:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("test policy repository root is unavailable")
        missing_roots = [path for path in test_roots if not (root / pathlib.PurePosixPath(path)).is_dir()]
        if missing_roots:
            raise ValueError(f"test_roots path is missing: {missing_roots}")
        missing_sources = []
        for source in coverage_sources:
            candidate = root / pathlib.PurePosixPath(source)
            module = root / pathlib.PurePosixPath(f"{source}.py")
            if not candidate.exists() and not module.is_file():
                missing_sources.append(source)
        if missing_sources:
            raise ValueError(f"coverage_sources path is missing: {missing_sources}")
        missing_critical = [path for path in all_critical if not (root / pathlib.PurePosixPath(path)).is_file()]
        if missing_critical:
            raise ValueError(f"critical_tests path is missing: {missing_critical}")
        missing_support = [
            path for path in protected_support_files if not (root / pathlib.PurePosixPath(path)).is_file()
        ]
        if missing_support:
            raise ValueError(f"protected_support_files path is missing: {missing_support}")

    return {
        "version": 1,
        "test_roots": test_roots,
        "marker_exclusions": markers,
        "registered_markers": registered_markers,
        "disabled_plugins": plugins,
        "coverage_sources": coverage_sources,
        "protected_support_files": protected_support_files,
        "critical_tests": critical_tests,
        "unexpected_skip_policy": "fail",
    }


def validate_profile_policy(policy: Mapping[str, Any], profile: str) -> None:
    if profile not in {"baseline", "python", "node", "powershell", "critical-ml"}:
        raise ValueError("test policy profile is invalid")
    if profile in {"baseline", "node", "powershell"}:
        return
    if not policy.get("test_roots"):
        raise ValueError("Python profile requires at least one test root")
    if not policy.get("coverage_sources"):
        raise ValueError("Python profile requires at least one coverage source")
    if profile == "critical-ml":
        critical = policy.get("critical_tests")
        if not isinstance(critical, Mapping):
            raise ValueError("critical-ml profile has no critical_tests manifest")
        missing = [category for category in sorted(CRITICAL_CATEGORIES) if not critical.get(category)]
        if missing:
            raise ValueError("critical-ml profile requires explicit manifest categories: " + ", ".join(missing))


def _marker_expression(markers: Sequence[str]) -> str:
    return " and ".join(f"not {marker}" for marker in markers)


def build_pytest_command(
    policy: Mapping[str, Any],
    *,
    junit_path: pathlib.Path,
    coverage_xml: pathlib.Path,
    coverage_json: pathlib.Path,
    trusted_site: pathlib.Path,
    target_root: pathlib.Path,
    target_site: pathlib.Path | None = None,
    protected_pytest_config: pathlib.Path | None = None,
) -> list[str]:
    command = [
        *_pytest_prefix(
            basetemp=pytest_basetemp_path(junit_path, "full"),
            trusted_site=trusted_site,
            target_root=target_root,
            target_site=target_site,
            registered_markers=policy.get("registered_markers", []),
            protected_pytest_config=protected_pytest_config,
        ),
        "-q",
        "-x",
        "--tb=short",
        "-W",
        "error",
        "-o",
        "addopts=",
        "-o",
        "console_output_style=classic",
    ]
    command.extend(("-p", "pytest_cov.plugin"))
    command.extend(_cache_provider_arguments())
    for plugin in policy["disabled_plugins"]:
        command.extend(("-p", f"no:{plugin}"))
    markers = _marker_expression(policy["marker_exclusions"])
    if markers:
        command.extend(("-m", markers))
    command.append(f"--junitxml={pytest_runtime_argument_path(junit_path, target_root)}")
    for source in policy["coverage_sources"]:
        command.append(f"--cov={source}")
    command.extend(
        (
            "--cov-branch",
            f"--cov-config={pytest_runtime_argument_path(COVERAGE_CONFIG, target_root)}",
            "--cov-report=term-missing",
            f"--cov-report=xml:{pytest_runtime_argument_path(coverage_xml, target_root)}",
            f"--cov-report=json:{pytest_runtime_argument_path(coverage_json, target_root)}",
        )
    )
    command.extend(policy["test_roots"])
    return command


def build_critical_command(
    policy: Mapping[str, Any],
    *,
    junit_path: pathlib.Path,
    trusted_site: pathlib.Path,
    collect_only: bool = False,
    target_root: pathlib.Path,
    target_site: pathlib.Path | None = None,
    protected_pytest_config: pathlib.Path | None = None,
) -> list[str]:
    """Build an unfiltered command for the protected critical-test manifest."""
    command = [
        *_pytest_prefix(
            basetemp=pytest_basetemp_path(junit_path, "critical"),
            trusted_site=trusted_site,
            target_root=target_root,
            target_site=target_site,
            registered_markers=policy.get("registered_markers", []),
            protected_pytest_config=protected_pytest_config,
        ),
        "-q",
        "--tb=short",
        "-W",
        "error",
        "-o",
        "addopts=",
        "-o",
        "console_output_style=classic",
        "-m",
        "",
    ]
    command.extend(_cache_provider_arguments())
    if collect_only:
        command.append("--collect-only")
    else:
        command.append("-x")
    for plugin in policy["disabled_plugins"]:
        command.extend(("-p", f"no:{plugin}"))
    if not collect_only:
        command.append(f"--junitxml={pytest_runtime_argument_path(junit_path, target_root)}")
    command.extend(path for category in sorted(CRITICAL_CATEGORIES) for path in policy["critical_tests"][category])
    return command


def build_fast_pytest_command(
    policy: Mapping[str, Any],
    *,
    selected_tests: Sequence[str],
    junit_path: pathlib.Path,
    trusted_site: pathlib.Path,
    target_root: pathlib.Path,
    target_site: pathlib.Path | None = None,
    protected_pytest_config: pathlib.Path | None = None,
) -> list[str]:
    """Build a fixed fast command for a prevalidated affected-test selection."""
    if not selected_tests or len(selected_tests) > 128:
        raise ValueError("fast pytest selection must be non-empty and bounded")
    declared_roots = policy["test_roots"]
    parsed = [_safe_repository_path(path, "fast selected test") for path in selected_tests]
    if parsed != sorted(set(parsed)):
        raise ValueError("fast pytest selection must be sorted and unique")
    if any(not path.endswith(".py") or not _path_under_roots(path, declared_roots) for path in parsed):
        raise ValueError("fast pytest selection escapes protected test roots")
    command = [
        *_pytest_prefix(
            basetemp=pytest_basetemp_path(junit_path, "fast"),
            trusted_site=trusted_site,
            target_root=target_root,
            target_site=target_site,
            registered_markers=policy.get("registered_markers", []),
            protected_pytest_config=protected_pytest_config,
        ),
        "-q",
        "-x",
        "--tb=short",
        "-W",
        "error",
        "-o",
        "addopts=",
        "-o",
        "console_output_style=classic",
    ]
    command.extend(_cache_provider_arguments())
    for plugin in policy["disabled_plugins"]:
        command.extend(("-p", f"no:{plugin}"))
    markers = _marker_expression(policy["marker_exclusions"])
    if markers:
        command.extend(("-m", markers))
    command.append(f"--junitxml={pytest_runtime_argument_path(junit_path, target_root)}")
    command.extend(parsed)
    return command


def canonical_policy_digest(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                policy,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def load_policy_file(
    path: pathlib.Path,
    *,
    root: pathlib.Path | None = None,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError:
        metadata = None
    if metadata is None or path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"test policy is missing: {path}")
    return validate_test_policy(parse_policy_bytes(path.read_bytes()), root=root)


def _discover_candidate_conftests(
    root: pathlib.Path,
    test_roots: Sequence[str],
) -> set[str]:
    """Enumerate conftest hooks without following candidate-controlled filesystem links."""
    discovered: set[str] = set()
    scanned_ancestors: set[pathlib.Path] = set()
    entries_seen = 0
    for relative_root in test_roots:
        parts = pathlib.PurePosixPath(relative_root).parts
        ancestor = root
        for part in ("", *parts[:-1]):
            if part:
                ancestor /= part
            if ancestor in scanned_ancestors:
                continue
            scanned_ancestors.add(ancestor)
            candidate = ancestor / "conftest.py"
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if candidate.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"candidate conftest is not a regular file: {candidate.relative_to(root)}")
            discovered.add(candidate.relative_to(root).as_posix())

        start = root / pathlib.PurePosixPath(relative_root)
        pending: list[tuple[pathlib.Path, int]] = [(start, 0)]
        while pending:
            current, depth = pending.pop()
            if depth > CONFTEST_SCAN_MAX_DEPTH:
                raise ValueError("candidate test tree exceeds the conftest scan depth limit")
            current_metadata = current.lstat()
            if current.is_symlink() or _is_reparse_point(current_metadata):
                raise ValueError(f"candidate test tree contains a link or reparse point: {current.relative_to(root)}")
            if not stat.S_ISDIR(current_metadata.st_mode):
                raise ValueError(f"candidate test root is not a regular directory: {current.relative_to(root)}")
            children = list(current.iterdir())
            entries_seen += len(children)
            if entries_seen > CONFTEST_SCAN_MAX_ENTRIES:
                raise ValueError("candidate test tree exceeds the conftest scan entry limit")
            for child in children:
                metadata = child.lstat()
                relative = child.relative_to(root).as_posix()
                if child.is_symlink() or _is_reparse_point(metadata):
                    raise ValueError(f"candidate test tree contains a link or reparse point: {relative}")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((child, depth + 1))
                elif child.name == "conftest.py":
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError(f"candidate conftest is not a regular file: {relative}")
                    discovered.add(relative)
    return discovered


def _protected_policy_paths(policy: Mapping[str, Any]) -> list[str]:
    return [path for category in sorted(CRITICAL_CATEGORIES) for path in policy["critical_tests"][category]] + list(
        policy["protected_support_files"]
    )


def _canonical_protected_bytes(raw: bytes, relative: str) -> bytes:
    try:
        return raw.decode("utf-8").replace("\r\n", "\n").encode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"protected test/support file is not UTF-8: {relative}") from error


def _validate_candidate_protected_policy(
    root: pathlib.Path,
    policy: Mapping[str, Any],
    expected_sha256: Mapping[str, str],
) -> None:
    candidate_conftests = _discover_candidate_conftests(root, policy["test_roots"])
    protected_conftests = {
        path for path in policy["protected_support_files"] if pathlib.PurePosixPath(path).name == "conftest.py"
    }
    unprotected_conftests = sorted(candidate_conftests - protected_conftests)
    if unprotected_conftests:
        raise ValueError("candidate checkout contains unprotected conftest hooks: " + ", ".join(unprotected_conftests))
    protected_paths = _protected_policy_paths(policy)
    if set(expected_sha256) != set(protected_paths) or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in expected_sha256.values()
    ):
        raise ValueError("protected-base manifest has an incomplete digest inventory")
    for relative in protected_paths:
        head_path = root / pathlib.PurePosixPath(relative)
        try:
            metadata = head_path.lstat()
        except OSError as error:
            raise ValueError(f"protected candidate test/support file is unavailable: {relative}") from error
        if head_path.is_symlink() or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"protected candidate test/support file is not regular: {relative}")
        resolved = head_path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError(f"protected candidate test/support file escapes the checkout: {relative}")
        actual = hashlib.sha256(_canonical_protected_bytes(head_path.read_bytes(), relative)).hexdigest()
        if actual != expected_sha256[relative]:
            raise ValueError(f"protected test/support bytes differ from the exact base: {relative}")


def load_policy_from_protected_manifest(
    root: pathlib.Path,
    manifest_path: pathlib.Path,
    base_sha: str,
) -> tuple[dict[str, Any], str]:
    """Load a supervisor-created base manifest without invoking git inside the runtime."""
    if not FULL_SHA.fullmatch(base_sha):
        raise ValueError("test policy base SHA is malformed")
    root = root.resolve()
    manifest_path = pathlib.Path(os.path.abspath(manifest_path))
    try:
        metadata = manifest_path.lstat()
    except OSError as error:
        raise ValueError("protected-base manifest is unavailable") from error
    if (
        manifest_path.is_symlink()
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > PROTECTED_BASE_MANIFEST_LIMIT
    ):
        raise ValueError("protected-base manifest is not a bounded regular file")
    resolved_manifest = manifest_path.resolve(strict=True)
    if resolved_manifest == root or root in resolved_manifest.parents:
        raise ValueError("protected-base manifest must be outside the candidate checkout")
    try:
        value = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("protected-base manifest is not valid UTF-8 JSON") from error
    if not isinstance(value, Mapping) or set(value) != {
        "base_sha",
        "policy",
        "protected_sha256",
        "schema_version",
    }:
        raise ValueError("protected-base manifest has an open schema")
    if value.get("schema_version") != 1 or value.get("base_sha") != base_sha:
        raise ValueError("protected-base manifest provenance differs from the requested base")
    policy_value = value.get("policy")
    protected_sha256 = value.get("protected_sha256")
    if not isinstance(policy_value, Mapping) or not isinstance(protected_sha256, Mapping):
        raise ValueError("protected-base manifest payload is malformed")
    policy = validate_test_policy(policy_value, root=root)
    _validate_candidate_protected_policy(root, policy, protected_sha256)
    return policy, canonical_policy_digest(policy)


def load_policy_from_base(
    root: pathlib.Path,
    base_sha: str,
) -> tuple[dict[str, Any], str]:
    """Load the exact protected-base policy; PR code cannot weaken selectors."""
    if not FULL_SHA.fullmatch(base_sha):
        raise ValueError("test policy base SHA is malformed")
    root = root.resolve()
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{base_sha}:{POLICY_PATH}"],
            cwd=root,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("protected base has no readable CI test policy") from error
    policy = validate_test_policy(parse_policy_bytes(raw), root=root)
    expected_sha256: dict[str, str] = {}
    for relative in _protected_policy_paths(policy):
        try:
            base_bytes = subprocess.check_output(
                ["git", "show", f"{base_sha}:{relative}"],
                cwd=root,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError(f"protected-base test/support file is unavailable: {relative}") from error
        expected_sha256[relative] = hashlib.sha256(_canonical_protected_bytes(base_bytes, relative)).hexdigest()
    _validate_candidate_protected_policy(root, policy, expected_sha256)
    return policy, canonical_policy_digest(policy)
