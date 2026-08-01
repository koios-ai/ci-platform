"""Run pinned pytest without site startup, plugin autoload, or target startup hooks."""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import sys
from typing import Protocol

REGISTERED_MARKERS = {
    "cli",
    "cli_quick",
    "cli_subprocess",
    "critical",
    "external",
    "gpu",
    "integration",
    "leakage",
    "requires_credentials",
    "requires_network",
    "resource_heavy",
    "slow",
    "smoke",
    "unit",
}

_POLICY_PATH = pathlib.Path(__file__).with_name("test_policy.py").resolve()
_POLICY_SPEC = importlib.util.spec_from_file_location("_ci_platform_test_policy", _POLICY_PATH)
if _POLICY_SPEC is None or _POLICY_SPEC.loader is None:
    raise RuntimeError("isolated pytest could not load the central test policy")
_POLICY_MODULE = importlib.util.module_from_spec(_POLICY_SPEC)
_POLICY_SPEC.loader.exec_module(_POLICY_MODULE)
remove_pytest_basetemp_path = _POLICY_MODULE.remove_pytest_basetemp_path
pytest_config_path = _POLICY_MODULE.pytest_config_path
remove_pytest_config = _POLICY_MODULE.remove_pytest_config
stage_pytest_config = _POLICY_MODULE.stage_pytest_config
validate_external_pytest_config = _POLICY_MODULE.validate_external_pytest_config


class _PytestConfig(Protocol):
    def addinivalue_line(self, name: str, line: str) -> None: ...


class _ProtectedMarkerRegistry:
    def __init__(self, markers: list[str]) -> None:
        self._markers = markers

    def pytest_configure(self, config: _PytestConfig) -> None:
        for marker in self._markers:
            config.addinivalue_line("markers", f"{marker}: protected-base declared marker")


def _within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def main() -> int:
    """Import trusted pytest/plugins first, then append target paths without site processing."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-site", type=pathlib.Path, required=True)
    parser.add_argument("--target-root", type=pathlib.Path, required=True)
    parser.add_argument("--target-site", type=pathlib.Path)
    parser.add_argument("--protected-config", type=pathlib.Path)
    parser.add_argument("--registered-marker", action="append", default=[])
    parser.add_argument("pytest_arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    trusted_site = args.trusted_site.resolve()
    target_root = args.target_root.resolve()
    if not trusted_site.is_dir() or not target_root.is_dir():
        raise ValueError("isolated pytest runtime paths are unavailable")
    if len(set(args.registered_marker)) != len(args.registered_marker) or any(
        marker not in REGISTERED_MARKERS for marker in args.registered_marker
    ):
        raise ValueError("isolated pytest received an invalid protected marker registry")
    sys.path.insert(0, str(trusted_site))
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ.pop("PYTEST_ADDOPTS", None)
    os.environ.pop("PYTEST_PLUGINS", None)
    import pytest

    pytest_path = pathlib.Path(pytest.__file__).resolve()
    if not _within(pytest_path, trusted_site):
        raise ValueError("pytest did not load from the trusted platform site")
    coverage_spec = importlib.util.find_spec("pytest_cov.plugin")
    if coverage_spec is None or coverage_spec.origin is None:
        raise ValueError("trusted pytest-cov plugin is unavailable")
    if not _within(pathlib.Path(coverage_spec.origin), trusted_site):
        raise ValueError("pytest-cov did not resolve from the trusted platform site")

    sys.path.append(str(target_root))
    if args.target_site is not None:
        target_site = args.target_site.resolve()
        if not target_site.is_dir():
            raise ValueError("isolated target site-packages path is unavailable")
        sys.path.append(str(target_site))
    os.chdir(target_root)
    arguments = list(args.pytest_arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    basetemp_values = [
        pathlib.Path(argument.partition("=")[2]) for argument in arguments if argument.startswith("--basetemp=")
    ]
    if len(basetemp_values) != 1:
        raise ValueError("isolated pytest requires exactly one trusted basetemp")
    basetemp = basetemp_values[0]
    if args.protected_config is None:
        expected_config = pytest_config_path(basetemp, target_root)
        expected_config_argument = os.path.relpath(expected_config, target_root)
    else:
        expected_config = validate_external_pytest_config(args.protected_config)
        expected_config_argument = str(expected_config)
    config_values = [
        arguments[index + 1] for index, argument in enumerate(arguments[:-1]) if argument in {"-c", "--inifile"}
    ]
    config_values.extend(argument.partition("=")[2] for argument in arguments if argument.startswith("--inifile="))
    if config_values != [expected_config_argument]:
        raise ValueError("isolated pytest requires exactly one derived immutable config")
    if args.protected_config is None:
        stage_pytest_config(basetemp, target_root)
    try:
        remove_pytest_basetemp_path(basetemp)
        try:
            return pytest.main(arguments, plugins=[_ProtectedMarkerRegistry(args.registered_marker)])
        finally:
            remove_pytest_basetemp_path(basetemp)
    finally:
        if args.protected_config is None:
            remove_pytest_config(basetemp, target_root, required=True)
        else:
            validate_external_pytest_config(expected_config)


if __name__ == "__main__":
    raise SystemExit(main())
