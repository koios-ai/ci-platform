"""Run untrusted consumer dependencies/tests in constrained OCI containers."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import urllib.parse
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import Any

import yaml

PYTHON_RUNTIME_IMAGE = "koios-ci-platform-python-runtime:v1"
PYTHON_BASE_IMAGE = (
    "python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"
)
NODE_RUNTIME_IMAGE = (
    "node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b"
)
POWERSHELL_RUNTIME_IMAGE = (
    "mcr.microsoft.com/powershell:7.5-ubuntu-24.04@"
    "sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81"
)
NODE_MANAGERS = {"npm": "10.9.2", "pnpm": "10.4.1", "yarn": "4.7.0"}
NODE_LOCKS = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}
NODE_REGISTRY_TAG = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
NODE_REGISTRY_RANGE = re.compile(r"^[0-9A-Za-z*+_.<>=~^| -]{1,200}$")
NODE_LOCKED_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_HOST_ENV = {
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "GITHUB_ENV",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_TOKEN",
}


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonregular_tracked_entries(root: pathlib.Path) -> None:
    """Reject symlinks, gitlinks, and unmerged entries before host target reads."""
    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "--stage", "-z"],
            cwd=root,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("tracked-file inventory is unavailable") from error
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, _path = record.split(b"\t", 1)
            mode, _object_id, stage = metadata.split()
        except ValueError as error:
            raise ValueError("tracked-file inventory is malformed") from error
        if mode not in {b"100644", b"100755"} or stage != b"0":
            raise ValueError("target contains a non-regular or unmerged tracked entry")


def _regular_target_file(root: pathlib.Path, relative: pathlib.PurePath | str) -> pathlib.Path:
    """Resolve one bounded regular candidate file without following a link."""
    root = root.resolve()
    candidate = root / relative
    try:
        candidate.relative_to(root)
        metadata = candidate.lstat()
    except (OSError, ValueError) as error:
        raise ValueError(f"candidate file is unavailable: {relative}") from error
    if not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink():
        raise ValueError(f"candidate file is not a regular non-symlink file: {relative}")
    resolved = candidate.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"candidate file escapes the target root: {relative}")
    return candidate


def _mount(source: pathlib.Path, destination: str, *, readonly: bool) -> str:
    value = f"type=bind,src={source.resolve()},dst={destination}"
    return f"{value},readonly" if readonly else value


def container_command(
    *,
    image: str,
    target: pathlib.Path | None,
    evidence: pathlib.Path | None,
    dependencies: pathlib.Path | None,
    network: str,
    arguments: Sequence[str],
    dependencies_read_only: bool = True,
    dependencies_destination: str = "/workspace/dependencies",
    platform: pathlib.Path | None = None,
    extra_mounts: Sequence[tuple[pathlib.Path, str, bool]] = (),
    workdir: str = "/workspace/target",
    entrypoint: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Build one shell-free Docker command with the fixed runtime boundary."""
    if network not in {"bridge", "none"}:
        raise ValueError("runtime container network must be bridge or none")
    command = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--network",
        network,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=536870912",
        "--workdir",
        workdir,
        "--env",
        "CI=true",
        "--env",
        "HOME=/tmp",
    ]
    if target is not None:
        command.extend(("--mount", _mount(target, "/workspace/target", readonly=True)))
    if dependencies is not None:
        command.extend(
            (
                "--mount",
                _mount(dependencies, dependencies_destination, readonly=dependencies_read_only),
            )
        )
    if evidence is not None:
        command.extend(("--mount", _mount(evidence, "/workspace/runtime-output", readonly=False)))
    if platform is not None:
        command.extend(("--mount", _mount(platform, "/opt/ci-platform", readonly=True)))
    for source, destination, readonly in extra_mounts:
        command.extend(("--mount", _mount(source, destination, readonly=readonly)))
    for name, value in sorted((environment or {}).items()):
        if name in FORBIDDEN_HOST_ENV or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
            raise ValueError(f"runtime container environment key is forbidden: {name}")
        command.extend(("--env", f"{name}={value}"))
    if entrypoint is not None:
        command.extend(("--entrypoint", entrypoint))
    command.append(image)
    command.extend(arguments)
    return command


def _prepare_writable(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(parents=True, exist_ok=True)
    if any(path.iterdir()):
        raise ValueError(f"isolated runtime directory must start empty: {path}")
    path.chmod(0o777)
    return path


def _safe_manifest_path(value: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    if (
        candidate.is_absolute()
        or len(candidate.parts) != 1
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value)
    ):
        raise ValueError(f"Python requirement include path is unsafe: {value!r}")
    return candidate


def _stage_python_manifests(target: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    """Copy only closed pinned requirement inputs; never expose source to a networked build."""
    source = target / "requirements.txt"
    if not source.is_file():
        raise ValueError("isolated Python dependency fetch requires a pinned requirements.txt")
    _prepare_writable(destination)
    pending = [pathlib.PurePosixPath("requirements.txt")]
    seen: set[pathlib.PurePosixPath] = set()
    package = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_,.-]+\])?"
        r"==[A-Za-z0-9][A-Za-z0-9_.+!-]*"
        r"(?:\s*;\s*[A-Za-z0-9_ .<>=!'\"()-]+)?$"
    )
    while pending:
        relative = pending.pop()
        if relative in seen or len(seen) >= 8:
            if relative in seen:
                continue
            raise ValueError("Python requirement include graph is oversized")
        seen.add(relative)
        try:
            text = _regular_target_file(target, relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"Python requirement manifest is unavailable: {relative}") from error
        if len(text.encode("utf-8")) > 256_000:
            raise ValueError("Python requirement manifest is oversized")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            include = re.fullmatch(r"(?:-r|--requirement|-c|--constraint)\s+([A-Za-z0-9_.-]+)", line)
            if include:
                pending.append(_safe_manifest_path(include.group(1)))
                continue
            if (
                "://" in line
                or "@" in line
                or "$" in line
                or line.startswith(("-", ".", "/"))
                or not package.fullmatch(line)
            ):
                raise ValueError(f"Python dependency is not a closed exact registry pin: {line!r}")
        (destination / relative).write_text(text, encoding="utf-8")
    destination.chmod(0o555)
    for relative in seen:
        (destination / relative).chmod(0o444)
    return destination


def python_runtime_plan(
    *,
    target: pathlib.Path,
    platform: pathlib.Path,
    evidence: pathlib.Path,
    protected_base_manifest: pathlib.Path,
    profile: str,
    base_sha: str,
    head_sha: str,
) -> list[list[str]]:
    if profile not in {"python", "critical-ml"} or not FULL_SHA.fullmatch(base_sha) or not FULL_SHA.fullmatch(head_sha):
        raise ValueError("Python runtime plan inputs are invalid")
    target_site = _prepare_writable(evidence.parent / "target-site")
    runtime_output = _prepare_writable(evidence.parent / "runtime-output")
    manifests = _stage_python_manifests(target, evidence.parent / "python-manifests")
    try:
        protected_metadata = protected_base_manifest.lstat()
    except OSError as error:
        raise ValueError("protected Python base manifest is unavailable") from error
    if protected_base_manifest.is_symlink() or not stat.S_ISREG(protected_metadata.st_mode):
        raise ValueError("protected Python base manifest is not a regular file")
    build = [
        "docker",
        "build",
        "--pull",
        "--file",
        str((platform / "docker" / "ci-python-runtime.Dockerfile").resolve()),
        "--tag",
        PYTHON_RUNTIME_IMAGE,
        str(platform.resolve()),
    ]
    dependency = container_command(
        image=PYTHON_RUNTIME_IMAGE,
        target=manifests,
        evidence=None,
        dependencies=target_site,
        dependencies_read_only=False,
        network="bridge",
        arguments=[
            "-I",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-compile",
            "--target",
            "/workspace/target-site",
            "--requirement",
            "/workspace/target/requirements.txt",
        ],
        dependencies_destination="/workspace/target-site",
        environment={
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PIP_NO_INPUT": "1",
        },
    )
    audit = container_command(
        image=PYTHON_RUNTIME_IMAGE,
        target=manifests,
        evidence=None,
        dependencies=None,
        network="bridge",
        arguments=[
            "-I",
            "-S",
            "/opt/ci-platform/scripts/run_module_isolated.py",
            "--trusted-site",
            "/opt/ci-platform-venv/lib/python3.12/site-packages",
            "--module",
            "pip_audit",
            "--",
            "--strict",
            "--requirement",
            "/workspace/target/requirements.txt",
        ],
        environment={
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PIP_NO_INPUT": "1",
        },
    )
    typing = container_command(
        image=PYTHON_RUNTIME_IMAGE,
        target=target,
        evidence=None,
        dependencies=target_site,
        network="none",
        arguments=[
            "-I",
            "-S",
            "/opt/ci-platform/scripts/run_module_isolated.py",
            "--trusted-site",
            "/opt/ci-platform-venv/lib/python3.12/site-packages",
            "--module",
            "mypy",
            "--",
            "--config-file",
            "/opt/ci-platform/contract/mypy-v1.ini",
            "--cache-dir",
            "/tmp/mypy-cache",
            ".",
        ],
        dependencies_destination="/workspace/target-site",
        environment={"MYPYPATH": "/workspace/target-site"},
    )
    test = container_command(
        image=PYTHON_RUNTIME_IMAGE,
        target=target,
        evidence=runtime_output,
        dependencies=target_site,
        network="none",
        arguments=[
            "-I",
            "-S",
            "/opt/ci-platform/scripts/run_platform_script.py",
            "--platform-root",
            "/opt/ci-platform",
            "--trusted-site",
            "/opt/ci-platform-venv/lib/python3.12/site-packages",
            "--script",
            "run_test_policy",
            "--",
            "--base-sha",
            base_sha,
            "--profile",
            profile,
            "--evidence-dir",
            "/workspace/runtime-output",
            "--coverage-xml",
            "/workspace/runtime-output/coverage.xml",
            "--coverage-json",
            "/workspace/runtime-output/coverage.json",
            "--trusted-site",
            "/opt/ci-platform-venv/lib/python3.12/site-packages",
            "--target-site",
            "/workspace/target-site",
            "--protected-base-manifest",
            "/workspace/protected-python-base.json",
            "--protected-pytest-config",
            "/opt/ci-platform/contract/pytest-v1.ini",
        ],
        dependencies_destination="/workspace/target-site",
        extra_mounts=((protected_base_manifest, "/workspace/protected-python-base.json", True),),
        environment={},
    )
    return [build, audit, dependency, typing, test]


def _verifier_module() -> ModuleType:
    path = pathlib.Path(__file__).with_name("verify_runtime_evidence.py")
    spec = importlib.util.spec_from_file_location("_ci_runtime_verifier", path)
    if spec is None or spec.loader is None:
        raise ValueError("runtime verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _test_policy_module() -> ModuleType:
    path = pathlib.Path(__file__).with_name("test_policy.py")
    spec = importlib.util.spec_from_file_location("_ci_runtime_test_policy", path)
    if spec is None or spec.loader is None:
        raise ValueError("test policy module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage_python_protected_base_manifest(
    target: pathlib.Path,
    destination: pathlib.Path,
    base_sha: str,
) -> pathlib.Path:
    """Materialize hashes from the trusted base so the runtime never needs git."""
    if not FULL_SHA.fullmatch(base_sha):
        raise ValueError("protected-base SHA is malformed")
    policy_module = _test_policy_module()
    policy, _policy_digest = policy_module.load_policy_from_base(target, base_sha)
    protected_sha256: dict[str, str] = {}
    for relative in policy_module._protected_policy_paths(policy):
        try:
            raw = subprocess.check_output(
                ["git", "show", f"{base_sha}:{relative}"],
                cwd=target,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError(f"protected-base test/support file is unavailable: {relative}") from error
        protected_sha256[relative] = hashlib.sha256(policy_module._canonical_protected_bytes(raw, relative)).hexdigest()
    root = _prepare_writable(destination)
    manifest = root / "protected-python-base.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "base_sha": base_sha,
                "policy": policy,
                "protected_sha256": protected_sha256,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    root.chmod(0o555)
    manifest.chmod(0o444)
    return manifest


def _is_node_registry_spec(value: str) -> bool:
    """Recognize only package-registry version/range/tag specs, never alternate sources."""
    if not value or value != value.strip() or len(value) > 200:
        return False
    lowered = value.lower()
    if (
        any(character in value for character in "/\\:@#?&%")
        or lowered.endswith((".tgz", ".tar", ".tar.gz", ".zip"))
        or any(ord(character) < 32 for character in value)
    ):
        return False
    if NODE_REGISTRY_TAG.fullmatch(value):
        return True
    return bool(NODE_REGISTRY_RANGE.fullmatch(value) and re.search(r"[0-9xX*]", value))


def _validate_node_spec_tree(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 16:
        raise ValueError(f"Node {label} exceeds the closed override depth")
    if isinstance(value, str):
        if not _is_node_registry_spec(value):
            raise ValueError(f"Node {label} may reference only registry version specs")
        return
    if not isinstance(value, Mapping) or len(value) > 1_000:
        raise ValueError(f"Node {label} must be a bounded object or registry version spec")
    for key, child in value.items():
        if not isinstance(key, str) or not key or len(key) > 214 or any(ord(character) < 32 for character in key):
            raise ValueError(f"Node {label} contains an invalid selector")
        _validate_node_spec_tree(child, label, depth=depth + 1)


def _node_configuration(target: pathlib.Path) -> tuple[str, str]:
    try:
        package = json.loads(
            _regular_target_file(target, "package.json").read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("Node package.json is unavailable or malformed") from error
    locks = [name for name in NODE_LOCKS if (target / name).exists() or (target / name).is_symlink()]
    if not isinstance(package, Mapping) or len(locks) != 1:
        raise ValueError("Node runtime requires exactly one supported lockfile")
    manager = NODE_LOCKS[locks[0]]
    declaration = f"{manager}@{NODE_MANAGERS[manager]}"
    if package.get("packageManager") != declaration:
        raise ValueError(f"Node runtime requires exact packageManager {declaration}")
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = package.get(field, {})
        if not isinstance(dependencies, Mapping):
            raise ValueError(f"Node {field} must be an object")
        for value in dependencies.values():
            if not isinstance(value, str) or not _is_node_registry_spec(value):
                raise ValueError("Node dependency manifests may reference only registry packages")
    for field in ("overrides", "resolutions"):
        if field in package:
            _validate_node_spec_tree(package[field], field)
    if "pnpm" in package:
        pnpm = package["pnpm"]
        if not isinstance(pnpm, Mapping) or set(pnpm) != {"overrides"}:
            raise ValueError("Node pnpm configuration has unsupported non-registry controls")
        _validate_node_spec_tree(pnpm["overrides"], "pnpm overrides")
    return manager, locks[0]


def _is_npm_registry_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and parsed.hostname == "registry.npmjs.org"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path.startswith("/")
        and len(parsed.path) > 1
        and not parsed.query
        and not parsed.fragment
    )


def _is_npm_registry_artifact_url(value: str) -> bool:
    if not _is_npm_registry_url(value):
        return False
    path = urllib.parse.urlsplit(value).path
    return "/-/" in path and path.endswith(".tgz")


def _is_canonical_sha512_sri(value: str) -> bool:
    prefix = "sha512-"
    if not value.startswith(prefix):
        return False
    try:
        encoded = value.removeprefix(prefix).encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return False
    return len(decoded) == 64 and base64.b64encode(decoded) == encoded


def _is_npm_package_name(value: str) -> bool:
    if re.fullmatch(r"[a-z0-9][a-z0-9._~-]{0,213}", value):
        return True
    return bool(re.fullmatch(r"@[a-z0-9][a-z0-9._~-]{0,99}/[a-z0-9][a-z0-9._~-]{0,99}", value))


def _is_package_lock_path(value: str) -> bool:
    if value == "":
        return True
    parts = value.split("/")
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules" or index + 1 >= len(parts):
            return False
        index += 1
        if parts[index].startswith("@"):
            if index + 1 >= len(parts) or not _is_npm_package_name(f"{parts[index]}/{parts[index + 1]}"):
                return False
            index += 2
        else:
            if not _is_npm_package_name(parts[index]):
                return False
            index += 1
    return True


def _validate_lock_spec_mapping(value: Any, label: str) -> None:
    if not isinstance(value, Mapping) or len(value) > 10_000:
        raise ValueError(f"Node lockfile {label} must be a bounded object")
    for name, spec in value.items():
        if not isinstance(name, str) or not _is_npm_package_name(name):
            raise ValueError(f"Node lockfile {label} contains an invalid package name")
        if not isinstance(spec, str) or not _is_node_registry_spec(spec):
            raise ValueError(f"Node lockfile {label} contains a non-registry dependency spec")


def _validate_package_lock_entry(path: str, value: Any) -> None:
    if not _is_package_lock_path(path) or not isinstance(value, Mapping) or len(value) > 100:
        raise ValueError("Node lockfile package entry has an invalid closed schema")
    allowed = {
        "bin",
        "cpu",
        "dependencies",
        "deprecated",
        "dev",
        "devDependencies",
        "devOptional",
        "engines",
        "funding",
        "hasInstallScript",
        "integrity",
        "license",
        "name",
        "optional",
        "optionalDependencies",
        "os",
        "peer",
        "peerDependencies",
        "peerDependenciesMeta",
        "resolved",
        "version",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"Node lockfile package entry has an open schema: {sorted(unknown)}")
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if field in value:
            _validate_lock_spec_mapping(value[field], field)
    if "engines" in value:
        engines = value["engines"]
        if (
            not isinstance(engines, Mapping)
            or len(engines) > 32
            or any(
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name)
                or not isinstance(spec, str)
                or not _is_node_registry_spec(spec)
                for name, spec in engines.items()
            )
        ):
            raise ValueError("Node lockfile engines field is malformed")
    for field in ("dev", "devOptional", "hasInstallScript", "optional", "peer"):
        if field in value and not isinstance(value[field], bool):
            raise ValueError(f"Node lockfile {field} flag is malformed")
    for field in ("cpu", "os"):
        if field in value and (
            not isinstance(value[field], list)
            or len(value[field]) > 64
            or any(
                not isinstance(item, str) or not re.fullmatch(r"!?[A-Za-z0-9._-]{1,64}", item) for item in value[field]
            )
        ):
            raise ValueError(f"Node lockfile {field} list is malformed")
    if "peerDependenciesMeta" in value:
        metadata = value["peerDependenciesMeta"]
        if not isinstance(metadata, Mapping) or len(metadata) > 1_000:
            raise ValueError("Node lockfile peer metadata is malformed")
        for name, settings in metadata.items():
            if (
                not isinstance(name, str)
                or not _is_npm_package_name(name)
                or not isinstance(settings, Mapping)
                or set(settings) != {"optional"}
                or not isinstance(settings["optional"], bool)
            ):
                raise ValueError("Node lockfile peer metadata is malformed")
    for field in ("name", "license", "deprecated"):
        if field in value and (
            not isinstance(value[field], str)
            or not value[field]
            or len(value[field]) > 2_000
            or any(ord(character) < 32 for character in value[field])
        ):
            raise ValueError(f"Node lockfile {field} metadata is malformed")
    for field in ("bin", "funding"):
        if field in value and not isinstance(value[field], (str, Mapping)):
            raise ValueError(f"Node lockfile {field} metadata is malformed")

    if "version" in value and (
        not isinstance(value["version"], str) or not NODE_LOCKED_VERSION.fullmatch(value["version"])
    ):
        raise ValueError("Node lockfile contains a non-registry dependency version")
    if "resolved" in value and (
        not isinstance(value["resolved"], str) or not _is_npm_registry_artifact_url(value["resolved"])
    ):
        raise ValueError("Node lockfile contains a non-registry dependency source")
    if "integrity" in value and (
        not isinstance(value["integrity"], str) or not _is_canonical_sha512_sri(value["integrity"])
    ):
        raise ValueError("Node lockfile package integrity is not one canonical sha512 SRI")
    if path and not {"version", "resolved", "integrity"} <= set(value):
        raise ValueError("Node lockfile registry package lacks version, resolution, or integrity")


def _validate_package_lock_value(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("Node lockfile root must be an object")
    allowed = {"lockfileVersion", "name", "packages", "requires", "version"}
    if set(value) - allowed:
        raise ValueError("Node lockfile root has an open schema")
    if value.get("lockfileVersion") != 3:
        raise ValueError("Node lockfile must use package-lock format v3")
    packages = value.get("packages")
    if not isinstance(packages, Mapping) or "" not in packages or len(packages) > 100_000:
        raise ValueError("Node lockfile v3 packages inventory is missing or oversized")
    if "requires" in value and not isinstance(value["requires"], bool):
        raise ValueError("Node lockfile requires flag is malformed")
    if "name" in value and (not isinstance(value["name"], str) or not _is_npm_package_name(value["name"])):
        raise ValueError("Node lockfile root package name is malformed")
    if "version" in value and (
        not isinstance(value["version"], str) or not NODE_LOCKED_VERSION.fullmatch(value["version"])
    ):
        raise ValueError("Node lockfile root package version is malformed")
    for path, entry in packages.items():
        if not isinstance(path, str):
            raise ValueError("Node lockfile package path is malformed")
        _validate_package_lock_entry(path, entry)


def _reject_duplicate_yaml_keys(node: yaml.nodes.Node, *, depth: int = 0) -> int:
    if depth > 32:
        raise ValueError("Node lockfile YAML exceeds the structural depth limit")
    count = 1
    if isinstance(node, yaml.nodes.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.nodes.ScalarNode) or key_node.value in seen:
                raise ValueError("Node lockfile YAML has a duplicate or non-scalar key")
            seen.add(key_node.value)
            count += _reject_duplicate_yaml_keys(value_node, depth=depth + 1)
    elif isinstance(node, yaml.nodes.SequenceNode):
        for child in node.value:
            count += _reject_duplicate_yaml_keys(child, depth=depth + 1)
    if count > 250_000:
        raise ValueError("Node lockfile YAML exceeds the structural node limit")
    return count


def _is_yarn_registry_resolution(value: str) -> bool:
    package, separator, spec = value.rpartition("@npm:")
    return bool(separator and _is_npm_package_name(package) and _is_node_registry_spec(spec))


def _validate_text_lock_structure(value: Any, manager: str, *, path: tuple[str, ...] = (), depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("Node lockfile exceeds the structural depth limit")
    if isinstance(value, Mapping):
        if len(value) > 100_000:
            raise ValueError("Node lockfile object is oversized")
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 1_000:
                raise ValueError("Node lockfile contains an invalid structural key")
            lowered = key.lower()
            if lowered in {"overrides", "resolutions"}:
                try:
                    _validate_node_spec_tree(child, f"{manager} lockfile {lowered}")
                except ValueError as error:
                    raise ValueError("Node lockfile contains a non-registry override") from error
            elif lowered in {"from", "tarball"}:
                if not isinstance(child, str) or not _is_npm_registry_artifact_url(child):
                    raise ValueError("Node lockfile contains a non-registry dependency source")
            elif lowered == "resolution":
                if manager == "yarn":
                    if not isinstance(child, str) or not _is_yarn_registry_resolution(child):
                        raise ValueError("Node lockfile contains a non-registry dependency resolution")
                elif isinstance(child, str):
                    if not _is_npm_registry_artifact_url(child):
                        raise ValueError("Node lockfile contains a non-registry dependency resolution")
                elif not isinstance(child, Mapping):
                    raise ValueError("Node lockfile dependency resolution is malformed")
            elif lowered == "specifier" and (not isinstance(child, str) or not _is_node_registry_spec(child)):
                raise ValueError("Node lockfile contains a non-registry dependency spec")
            elif lowered == "integrity" and (not isinstance(child, str) or not _is_canonical_sha512_sri(child)):
                raise ValueError("Node lockfile package integrity is not one canonical sha512 SRI")
            _validate_text_lock_structure(child, manager, path=(*path, key), depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 100_000:
            raise ValueError("Node lockfile sequence is oversized")
        for child in value:
            _validate_text_lock_structure(child, manager, path=path, depth=depth + 1)
        return
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError("Node lockfile contains an unsupported YAML value")


def _validate_node_lock(target: pathlib.Path, lock: str) -> None:
    path = _regular_target_file(target, lock)
    raw = path.read_bytes()
    if len(raw) > 5_000_000:
        raise ValueError("Node lockfile is oversized")
    if lock == "package-lock.json":
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("package-lock.json is malformed") from error
        _validate_package_lock_value(value)
        return
    try:
        text = raw.decode("utf-8")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        if node is None:
            raise ValueError("Node lockfile YAML is empty")
        _reject_duplicate_yaml_keys(node)
        value = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("Node lockfile is not bounded valid UTF-8 YAML") from error
    lowered = text.lower()
    if re.search(
        r"(?:git\+|git@|ssh:|file:|link:|workspace:|github:|gitlab:|bitbucket:|github\.com|gitlab\.com|bitbucket\.org|codeload\.)",
        lowered,
    ):
        raise ValueError("Node lockfile contains a non-registry dependency source")
    for url in re.findall(r"https?://[^\s\"']+", text):
        if not _is_npm_registry_url(url.rstrip(",)]}")):
            raise ValueError("Node lockfile contains a non-registry dependency URL")
    if not isinstance(value, Mapping):
        raise ValueError("Node lockfile YAML root must be an object")
    if lock == "pnpm-lock.yaml":
        if value.get("lockfileVersion") != "9.0":
            raise ValueError("Node pnpm lockfile must use the supported format 9.0")
        manager = "pnpm"
    else:
        metadata = value.get("__metadata")
        if not isinstance(metadata, Mapping) or metadata.get("version") != 8:
            raise ValueError("Node Yarn lockfile must use the supported metadata version 8")
        manager = "yarn"
    _validate_text_lock_structure(value, manager)


def _materialize_node_build(target: pathlib.Path, directory: pathlib.Path, lock: str) -> None:
    _prepare_writable(directory)
    _validate_node_lock(target, lock)
    if (target / ".yarnrc.yml").exists():
        raise ValueError("candidate Yarn configuration is unsupported at the network boundary")
    for name in ("package.json", lock):
        shutil.copyfile(_regular_target_file(target, name), directory / name)
    if lock == "yarn.lock":
        (directory / ".yarnrc.yml").write_text(
            'nodeLinker: node-modules\nnpmRegistryServer: "https://registry.npmjs.org"\nenableScripts: false\n',
            encoding="utf-8",
        )


def _node_audit_command(manager: str) -> list[str]:
    if manager not in NODE_MANAGERS:
        raise ValueError("unsupported Node package manager")
    return {
        "npm": [
            "npm",
            "audit",
            "--audit-level=low",
            "--include=prod",
            "--include=dev",
        ],
        "pnpm": [
            "corepack",
            f"pnpm@{NODE_MANAGERS['pnpm']}",
            "audit",
            "--audit-level=low",
        ],
        "yarn": [
            "corepack",
            f"yarn@{NODE_MANAGERS['yarn']}",
            "npm",
            "audit",
            "--all",
            "--recursive",
            "--severity=low",
        ],
    }[manager]


def _npm_manager_verification() -> list[str]:
    expected = NODE_MANAGERS["npm"]
    script = (
        "const fs=require('node:fs');"
        "const p='/usr/local/lib/node_modules/npm/package.json';"
        "const v=JSON.parse(fs.readFileSync(p,'utf8')).version;"
        f"if(v!=='{expected}'){{process.stderr.write('unexpected image-bound npm version\\n');process.exit(86)}}"
    )
    return ["node", "-e", script]


def node_runtime_plan(
    *,
    target: pathlib.Path,
    platform: pathlib.Path,
    evidence: pathlib.Path,
    base_sha: str,
) -> tuple[list[list[str]], Mapping[str, Any]]:
    verifier = _verifier_module()
    policy = verifier.load_node_policy_from_base(target, base_sha)
    manager, lock = _node_configuration(target)
    if manager in {"pnpm", "yarn"}:
        raise ValueError(f"{manager} runtime is blocked until its Corepack artifact is digest-bound")
    _validate_node_lock(target, lock)
    build_root = evidence.parent / "node-build"
    _materialize_node_build(target, build_root, lock)
    runtime_output = _prepare_writable(evidence.parent / "runtime-output")
    policy_root = evidence.parent / "protected-policy"
    _prepare_writable(policy_root)
    policy_path = policy_root / "node-policy.json"
    policy_path.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")
    policy_root.chmod(0o555)
    policy_path.chmod(0o444)
    manager_verification = container_command(
        image=NODE_RUNTIME_IMAGE,
        target=None,
        evidence=None,
        dependencies=None,
        network="none",
        arguments=_npm_manager_verification(),
        workdir="/tmp",
    )
    install = ["npm", "ci", "--ignore-scripts", "--no-audit", "--fund=false"]
    dependency = container_command(
        image=NODE_RUNTIME_IMAGE,
        target=None,
        evidence=None,
        dependencies=build_root,
        dependencies_read_only=False,
        network="bridge",
        arguments=install,
        workdir="/workspace/dependencies",
        environment={
            "COREPACK_HOME": "/tmp/corepack",
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org",
            "NPM_CONFIG_USERCONFIG": "/dev/null",
        },
    )
    audit = container_command(
        image=NODE_RUNTIME_IMAGE,
        target=None,
        evidence=None,
        dependencies=build_root,
        dependencies_read_only=True,
        network="bridge",
        arguments=_node_audit_command(manager),
        workdir="/workspace/dependencies",
        environment={
            "COREPACK_HOME": "/tmp/corepack",
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org",
            "NPM_CONFIG_USERCONFIG": "/dev/null",
        },
    )
    node_modules = build_root / "node_modules"
    test = container_command(
        image=NODE_RUNTIME_IMAGE,
        target=target,
        evidence=runtime_output,
        dependencies=node_modules,
        dependencies_destination="/workspace/target/node_modules",
        network="none",
        platform=platform,
        extra_mounts=((policy_path, "/workspace/node-policy.json", True),),
        arguments=[
            "node",
            "/opt/ci-platform/scripts/run_node_test_policy.mjs",
            "--policy",
            "/workspace/node-policy.json",
            "--output",
            "/workspace/runtime-output",
        ],
    )
    return [manager_verification, dependency, audit, test], policy


def powershell_runtime_plan(
    *,
    target: pathlib.Path,
    platform: pathlib.Path,
    evidence: pathlib.Path,
) -> list[list[str]]:
    del target, platform, evidence
    raise ValueError("PowerShell runtime is blocked until a digest-bound Pester 5.7.1 artifact is available")


def _docker_environment() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if name not in FORBIDDEN_HOST_ENV}


def _run(
    command: Sequence[str], *, timeout: int = 3600, capture_output: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=True,
        timeout=timeout,
        text=True,
        capture_output=capture_output,
        env=_docker_environment(),
    )


def _image_digest(image: str) -> str:
    if "@sha256:" in image:
        return image.split("@", 1)[1]
    result = _run(["docker", "image", "inspect", "--format={{.Id}}", image], timeout=60, capture_output=True)
    digest = result.stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("built runtime image has no immutable image ID")
    return digest


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    ).hexdigest()


def _promote(
    *,
    scratch: pathlib.Path,
    evidence: pathlib.Path,
    payload_files: set[str],
    profile: str,
    base_sha: str,
    head_sha: str,
    platform_sha: str,
    workflow_attempt: int,
    image_digest: str,
    policy_digest: str,
) -> None:
    if evidence.exists() and any(evidence.iterdir()):
        raise ValueError("final runtime evidence directory must start empty")
    evidence.mkdir(parents=True, exist_ok=True)
    evidence.chmod(0o700)
    for relative in sorted(payload_files):
        shutil.copyfile(scratch / relative, evidence / relative)
    hashes = {
        relative: hashlib.sha256((evidence / relative).read_bytes()).hexdigest() for relative in sorted(payload_files)
    }
    attestation = {
        "schema_version": 1,
        "status": "captured-after-target-exit",
        "profile": profile,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "platform_sha": platform_sha,
        "workflow_attempt": workflow_attempt,
        "image_digest": image_digest,
        "policy_digest": policy_digest,
        "evidence_sha256": hashes,
    }
    (evidence / "runtime-attestation.json").write_text(
        json.dumps(attestation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def execute(
    *,
    target: pathlib.Path,
    platform: pathlib.Path,
    evidence: pathlib.Path,
    profile: str,
    base_sha: str,
    head_sha: str,
    platform_sha: str,
    workflow_attempt: int,
) -> None:
    if any(not FULL_SHA.fullmatch(value) for value in (base_sha, head_sha, platform_sha)):
        raise ValueError("runtime provenance SHA is malformed")
    if workflow_attempt <= 0:
        raise ValueError("workflow attempt must be positive")
    target = target.resolve()
    platform = platform.resolve()
    evidence = evidence.resolve()
    _reject_nonregular_tracked_entries(target)
    target_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    platform_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=platform, text=True).strip()
    if target_head != head_sha or platform_head != platform_sha:
        raise ValueError("runtime checkout provenance does not match the requested target/platform SHA")
    verifier = _verifier_module()
    if profile in {"python", "critical-ml"}:
        protected_base_manifest = _stage_python_protected_base_manifest(
            target,
            evidence.parent / "protected-python-base",
            base_sha,
        )
        plan = python_runtime_plan(
            target=target,
            platform=platform,
            evidence=evidence,
            protected_base_manifest=protected_base_manifest,
            profile=profile,
            base_sha=base_sha,
            head_sha=head_sha,
        )
        for command in plan:
            _run(command)
        scratch = evidence.parent / "runtime-output"
        verifier.verify_python_evidence(scratch, profile=profile, base_sha=base_sha)
        summary = json.loads((scratch / "test-policy-summary.json").read_text(encoding="utf-8"))
        _promote(
            scratch=scratch,
            evidence=evidence,
            payload_files=verifier.PYTHON_EVIDENCE_FILES,
            profile=profile,
            base_sha=base_sha,
            head_sha=head_sha,
            platform_sha=platform_sha,
            workflow_attempt=workflow_attempt,
            image_digest=_image_digest(PYTHON_RUNTIME_IMAGE),
            policy_digest=summary["policy_digest"],
        )
    elif profile == "node":
        plan, policy = node_runtime_plan(
            target=target,
            platform=platform,
            evidence=evidence,
            base_sha=base_sha,
        )
        for command in plan:
            _run(command)
        scratch = evidence.parent / "runtime-output"
        verifier.verify_node_evidence(scratch, policy)
        _promote(
            scratch=scratch,
            evidence=evidence,
            payload_files=verifier.NODE_EVIDENCE_FILES,
            profile=profile,
            base_sha=base_sha,
            head_sha=head_sha,
            platform_sha=platform_sha,
            workflow_attempt=workflow_attempt,
            image_digest=_image_digest(NODE_RUNTIME_IMAGE),
            policy_digest=_canonical_digest(policy),
        )
    elif profile == "powershell":
        for command in powershell_runtime_plan(target=target, platform=platform, evidence=evidence):
            _run(command)
        scratch = evidence.parent / "runtime-output"
        verifier.verify_powershell_evidence(scratch)
        _promote(
            scratch=scratch,
            evidence=evidence,
            payload_files=verifier.POWERSHELL_EVIDENCE_FILES,
            profile=profile,
            base_sha=base_sha,
            head_sha=head_sha,
            platform_sha=platform_sha,
            workflow_attempt=workflow_attempt,
            image_digest=_image_digest(POWERSHELL_RUNTIME_IMAGE),
            policy_digest=hashlib.sha256(b"pester-all-tests-v1\n").hexdigest(),
        )
    elif profile == "baseline":
        scratch = _prepare_writable(evidence.parent / "runtime-output")
        value = {"profile": "baseline", "reason": "no runtime tests", "status": "not-applicable"}
        (scratch / "runtime-not-applicable.json").write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        verifier.verify_baseline_evidence(scratch)
        _promote(
            scratch=scratch,
            evidence=evidence,
            payload_files=verifier.BASELINE_EVIDENCE_FILES,
            profile=profile,
            base_sha=base_sha,
            head_sha=head_sha,
            platform_sha=platform_sha,
            workflow_attempt=workflow_attempt,
            image_digest="sha256:" + hashlib.sha256(b"no-runtime-image\n").hexdigest(),
            policy_digest=hashlib.sha256(b"baseline-runtime-not-applicable-v1\n").hexdigest(),
        )
    else:
        raise ValueError("unsupported runtime profile")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=pathlib.Path, required=True)
    parser.add_argument("--platform", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--profile", choices=("baseline", "python", "node", "powershell", "critical-ml"), required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--platform-sha", required=True)
    parser.add_argument("--workflow-attempt", type=int, required=True)
    args = parser.parse_args()
    execute(
        target=args.target,
        platform=args.platform,
        evidence=args.evidence_dir,
        profile=args.profile,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        platform_sha=args.platform_sha,
        workflow_attempt=args.workflow_attempt,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
