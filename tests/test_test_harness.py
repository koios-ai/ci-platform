from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL_WRAPPER = ROOT / "scripts" / "run-tests.ps1"
SHELL_WRAPPER = ROOT / "scripts" / "run-tests.sh"
WINDOWS_GIT_BASH_CANDIDATES = (
    Path(r"C:\Program Files\Git\bin\bash.exe"),
    Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
)
COMPLETE_PLATFORM_SUITE_TIMEOUT_SECONDS = 120
COMPLETE_PLATFORM_SUITE_WORKERS = "2"


def _shell_wrapper_source() -> str:
    """Feed LF-only source to WSL/Git Bash even when Git checked out CRLF."""
    return SHELL_WRAPPER.read_text(encoding="utf-8").replace("\r\n", "\n")


def _shell_probe(body: str) -> str:
    """Run a wrapper probe entirely inside the POSIX shell's own temporary tree."""
    return f"""\
set -u
probe_parent="$(cd -- "${{TMPDIR:-/tmp}}" && pwd -P)"
test -d "$probe_parent"
test ! -L "$probe_parent"
probe_root="$(mktemp -d "$probe_parent/ci-platform-wrapper-probe.XXXXXX")"
case "$probe_root" in
  "$probe_parent"/ci-platform-wrapper-probe.??????) ;;
  *) exit 97 ;;
esac
test -d "$probe_root"
test ! -L "$probe_root"
cleanup_probe() {{
  cleanup_status=$?
  cd -- "$probe_parent" || return 98
  case "$probe_root" in
    "$probe_parent"/ci-platform-wrapper-probe.??????) ;;
    *) return 98 ;;
  esac
  test -d "$probe_root" || return 98
  test ! -L "$probe_root" || return 98
  test -z "$(find "$probe_root" -mindepth 1 -maxdepth 4 \\( -type l -o \\( ! -type f ! -type d \\) \\) -print -quit)"
  find "$probe_root" -depth -mindepth 1 -maxdepth 4 -type f -exec rm -- {{}} \\;
  find "$probe_root" -depth -mindepth 1 -maxdepth 4 -type d -exec rmdir -- {{}} \\;
  rmdir -- "$probe_root"
  return "$cleanup_status"
}}
trap cleanup_probe EXIT
cd "$probe_root"
{body}
"""


def _verified_bash() -> tuple[str, dict[str, str]]:
    """Resolve one bounded, regular Bash runtime and reject the Windows WSL app alias."""
    if os.name == "nt":
        candidates = list(WINDOWS_GIT_BASH_CANDIDATES)
        canary = (
            'case "$(uname -s)" in MINGW*|MSYS*) ;; *) exit 97;; esac; '
            "command -v mktemp >/dev/null && command -v rm >/dev/null && "
            "command -v find >/dev/null"
        )
    else:
        discovered = shutil.which("bash")
        candidates = [Path(discovered)] if discovered is not None else []
        canary = "command -v mktemp >/dev/null && command -v rm >/dev/null && command -v find >/dev/null"
    failures: list[str] = []
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    for candidate in candidates[:3]:
        try:
            metadata = candidate.lstat()
        except OSError as error:
            failures.append(f"{candidate}: {error.__class__.__name__}")
            continue
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if candidate.is_symlink() or attributes & reparse_flag or not stat.S_ISREG(metadata.st_mode):
            failures.append(f"{candidate}: not a regular executable")
            continue
        resolved = candidate.resolve(strict=True)
        environment = os.environ.copy()
        if os.name == "nt":
            git_root = candidate.parents[2] if candidate.parent.parent.name == "usr" else candidate.parents[1]
            runtime_directories = (git_root / "usr" / "bin", git_root / "mingw64" / "bin")
            invalid_runtime_directory = False
            for runtime_directory in runtime_directories:
                try:
                    runtime_metadata = runtime_directory.lstat()
                except OSError:
                    invalid_runtime_directory = True
                    break
                runtime_attributes = int(getattr(runtime_metadata, "st_file_attributes", 0))
                if (
                    runtime_directory.is_symlink()
                    or runtime_attributes & reparse_flag
                    or not stat.S_ISDIR(runtime_metadata.st_mode)
                ):
                    invalid_runtime_directory = True
                    break
            if invalid_runtime_directory:
                failures.append(f"{candidate}: Git Bash runtime directories are unavailable")
                continue
            environment["PATH"] = os.pathsep.join(str(path.resolve(strict=True)) for path in runtime_directories)
        probe = subprocess.run(
            [str(resolved), "-c", canary],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        if probe.returncode == 0:
            return str(resolved), environment
        failures.append(f"{candidate}: canary exited {probe.returncode}")
    pytest.fail("no verified Bash runtime is available: " + "; ".join(failures), pytrace=False)


def _failing_test(tmp_path: Path) -> Path:
    path = tmp_path / "test_fails.py"
    path.write_text("def test_fails():\n    assert False\n", encoding="utf-8")
    return path


def complete_platform_suite_command(*, disable_plugin_autoload: bool) -> list[str]:
    command = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "tests",
        "-q",
        "--ignore=tests/test_test_harness.py",
    ]
    if disable_plugin_autoload:
        command.extend(["-p", "xdist.plugin"])
    command.extend(["-n", COMPLETE_PLATFORM_SUITE_WORKERS])
    return command


def test_complete_platform_suite_commands_use_two_bounded_workers() -> None:
    """Catches timeout recovery weakening the watchdog or relying on unbounded worker discovery."""
    assert COMPLETE_PLATFORM_SUITE_TIMEOUT_SECONDS == 120
    normal = complete_platform_suite_command(disable_plugin_autoload=False)
    isolated = complete_platform_suite_command(disable_plugin_autoload=True)
    assert normal[-2:] == ["-n", "2"]
    assert "xdist.plugin" not in normal
    assert isolated[-4:] == ["-p", "xdist.plugin", "-n", "2"]
    assert normal[:-2] == isolated[:-4]


@pytest.mark.parametrize("disable_plugin_autoload", [False, True])
def test_complete_platform_suite_runs_in_each_plugin_mode(disable_plugin_autoload: bool) -> None:
    """Catches forced plugin registration that breaks ordinary pytest autoload."""
    environment = os.environ.copy()
    if disable_plugin_autoload:
        environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    else:
        environment.pop("PYTEST_DISABLE_PLUGIN_AUTOLOAD", None)

    result = subprocess.run(
        complete_platform_suite_command(disable_plugin_autoload=disable_plugin_autoload),
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=COMPLETE_PLATFORM_SUITE_TIMEOUT_SECONDS,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_powershell_wrapper_preserves_pytest_failure_after_cleanup(tmp_path: Path) -> None:
    """Catches a successful cleanup command masking a failed PowerShell test run."""
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    artifacts = tmp_path / "artifacts"
    environment = os.environ.copy()
    environment["CI_PLATFORM_TEST_ARTIFACTS_DIR"] = str(artifacts)

    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-File",
            str(POWERSHELL_WRAPPER),
            "-Python",
            sys.executable,
            str(_failing_test(tmp_path)),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert artifacts.is_dir()
    assert not any(artifacts.iterdir())
    assert not (tmp_path / ".pytest_cache").exists()
    assert not (tmp_path / "pytest-junit.xml").exists()


def test_shell_wrapper_preserves_pytest_failure_after_cleanup() -> None:
    """Catches a successful cleanup command masking a failed POSIX shell test run."""
    shell, shell_environment = _verified_bash()
    probe = _shell_probe(
        f"""\
export CI_PLATFORM_TEST_ARTIFACTS_DIR=artifacts
export PYTHON=false
set +e
(
{_shell_wrapper_source()}
)
wrapper_status=$?
set -e
test "$wrapper_status" -eq 1
test -d artifacts
test -z "$(find artifacts -mindepth 1 -maxdepth 1 -print -quit)"
test ! -e .pytest_cache
test ! -e pytest-junit.xml
"""
    )

    result = subprocess.run(
        [shell, "-s"],
        check=False,
        capture_output=True,
        timeout=30,
        input=probe.encode("utf-8"),
        env=shell_environment,
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")

    assert result.returncode == 0, output


def test_shell_wrapper_fails_before_pytest_when_temporary_setup_is_unwritable() -> None:
    """Catches a shell wrapper that falls through to pytest after artifact setup fails."""
    shell, shell_environment = _verified_bash()
    probe = _shell_probe(
        f"""\
printf 'not a directory\\n' > blocked-artifact-parent
export CI_PLATFORM_TEST_ARTIFACTS_DIR=blocked-artifact-parent
export PYTHON=false
set +e
(
{_shell_wrapper_source()}
)
wrapper_status=$?
set -e
test "$wrapper_status" -eq 1
"""
    )

    result = subprocess.run(
        [shell, "-s"],
        check=False,
        capture_output=True,
        timeout=30,
        input=probe.encode("utf-8"),
        env=shell_environment,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")

    assert result.returncode == 0, stdout + stderr
    assert "mkdir:" in stderr
    assert "1 passed" not in stdout
