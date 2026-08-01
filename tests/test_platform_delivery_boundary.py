from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_ci_platform_v1.py"


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("validate_ci_platform_v1_publication", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    scripts = str(ROOT / "scripts")
    sys.path.insert(0, scripts)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(scripts)
    return module


def copy_publication_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "platform"
    (fixture / "contract").mkdir(parents=True)
    for relative in (
        "README.md",
        "contract/v1.json",
        "contract/secret-scan-v1.json",
        "contract/public-prerelease-v1.json",
    ):
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    (fixture / "control.py").write_text("print('safe publication canary')\n", encoding="utf-8")
    manifest_path = fixture / "contract/public-prerelease-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_count"], manifest["artifact_tree_sha256"] = load_validator()._publication_tree_attestation(
        fixture
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return fixture


def test_preflight_never_uses_consumer_token_for_central_repository_rest() -> None:
    source = (ROOT / ".github" / "actions" / "final-preflight" / "preflight.py").read_text(encoding="utf-8")
    assert 'f"/repos/{ACTION_REPOSITORY}/actions/workflows/' not in source
    assert 'run.get("workflow_url")' in source
    assert 'run.get("path")' in source


def test_public_prerelease_publication_is_authorized_without_authorizing_cutover() -> None:
    contract = json.loads((ROOT / "contract" / "v1.json").read_text(encoding="utf-8"))
    delivery = contract["x-platform-delivery"]
    assert delivery == {
        "current_required_and_final_workflow_dependency": "cross-repository-checkout",
        "distribution": "sanitized-public-prerelease",
        "public_repository_authorized": True,
        "public_prerelease_publication_permitted": True,
        "hosted_canary_use_only": True,
        "consumer_pin_permitted": False,
        "ruleset_activation_permitted": False,
        "source_history_publication_permitted": False,
        "publication_history": "sanitized-root-snapshot-only",
        "prerelease_manifest": "contract/public-prerelease-v1.json",
        "pat_permitted": False,
    }
    blockers = {item["id"] for item in contract["x-rollout-status"]["blocking_requirements"]}
    assert "private-platform-delivery" not in blockers
    assert "supported-release-manifest" in blockers
    assert contract["x-platform-release-policy"] == {
        "current_head_only": True,
        "staged_rollout_supported": False,
        "arbitrary_historical_sha_permitted": False,
        "public_prerelease_manifest": "contract/public-prerelease-v1.json",
        "public_prerelease_support": "hosted-canaries-only",
        "required_resolution": ("protected-supported-release-manifest-with-closed-template-digests"),
    }
    assert contract["x-rollout-status"]["cutover_permitted"] is False
    assert contract["x-rollout-status"]["disposition"] == "NOT READY"

    for relative in (
        ".github/workflows/required.yml",
        ".github/workflows/reusable-final.yml",
    ):
        raw = (ROOT / relative).read_text(encoding="utf-8")
        assert "repository: ${{ job.workflow_repository }}" in raw


def test_public_prerelease_manifest_binds_the_publishable_runtime_tree() -> None:
    """Catches publishing runtime bytes that are absent from or drift from the canary-only attestation."""
    load_validator().validate_publication_boundary(ROOT)


def test_public_prerelease_manifest_rejects_runtime_drift(tmp_path: Path) -> None:
    """Catches a post-attestation executable edit being treated as an authenticated pre-release."""
    fixture = copy_publication_fixture(tmp_path)
    target = fixture / "control.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")

    with pytest.raises(ValueError, match="digest"):
        load_validator().validate_publication_boundary(fixture)


def test_canonical_archive_passes_while_autocrlf_checkout_fails_closed(tmp_path: Path) -> None:
    """Catches publishing checkout-transformed bytes instead of the canonical Git snapshot."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    safe_archive_command = (
        'git -C "$SANITIZED_SOURCE" -c core.autocrlf=false archive '
        '--format=tar --output="$ARCHIVE_PATH" "$SANITIZED_ROOT_SHA"'
    )
    assert safe_archive_command in readme
    assert "outside the sanitized source tree" in readme.lower()
    assert "autocrlf-transformed checkouts must fail closed" in readme.lower()

    source = tmp_path / "platform"
    (source / "contract").mkdir(parents=True)
    for relative in (
        "README.md",
        "contract/v1.json",
        "contract/secret-scan-v1.json",
        "contract/public-prerelease-v1.json",
    ):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    module = load_validator()
    manifest_path = source / "contract/public-prerelease-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_count"], manifest["artifact_tree_sha256"] = module._publication_tree_attestation(source)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    commands = (
        ["git", "init", "--quiet", "--initial-branch=main"],
        ["git", "config", "core.autocrlf", "false"],
        ["git", "config", "user.name", "CI"],
        ["git", "config", "user.email", "ci@example.invalid"],
        ["git", "add", "-A"],
        ["git", "commit", "--quiet", "-m", "canonical public snapshot"],
    )
    for command in commands:
        result = subprocess.run(command, cwd=source, check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

    archive = tmp_path / "canonical.tar"
    canonical = tmp_path / "canonical-export"
    canonical.mkdir()
    result = subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "core.autocrlf=false",
            "archive",
            "--format=tar",
            f"--output={archive}",
            "HEAD",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    with tarfile.open(archive, mode="r") as bundle:
        bundle.extractall(canonical, filter="data")

    transformed = tmp_path / "autocrlf-checkout"
    result = subprocess.run(
        ["git", "clone", "--quiet", "--no-checkout", "--local", str(source), str(transformed)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    for command in (
        ["git", "config", "core.autocrlf", "true"],
        ["git", "checkout", "--quiet", "--detach", "HEAD"],
    ):
        result = subprocess.run(command, cwd=transformed, check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

    assert b"\r\n" not in (canonical / "README.md").read_bytes()
    assert b"\r\n" in (transformed / "README.md").read_bytes()
    expected = module._publication_tree_attestation(canonical)
    assert module._publication_tree_attestation(transformed) != expected
    module.validate_publication_boundary(canonical)
    with pytest.raises(ValueError, match="artifact count or digest"):
        module.validate_publication_boundary(transformed)


@pytest.mark.parametrize(
    ("parts", "diagnostic"),
    [
        (("AK", "IA", "A" * 16), "aws-access-key"),
        (("-----BE", "GIN PRIVATE ", "KEY-----"), "private-key"),
    ],
)
def test_publication_rejects_every_pinned_secret_class(
    tmp_path: Path,
    parts: tuple[str, ...],
    diagnostic: str,
) -> None:
    """Catches publication scanning only a hand-picked subset of the pinned secret policy."""
    fixture = copy_publication_fixture(tmp_path)
    (fixture / "synthetic-secret.txt").write_text("".join(parts), encoding="utf-8")

    with pytest.raises(ValueError, match=diagnostic):
        load_validator().validate_publication_boundary(fixture)


def test_publication_inventory_rejects_tracked_non_regular_git_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches a Git symlink or gitlink being treated as a regular publication artifact."""
    root = tmp_path / "publication"
    root.mkdir()
    (root / "linked-entry").write_text("safe", encoding="utf-8")
    module = load_validator()

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        output = b"120000 " + b"a" * 40 + b" 0\tlinked-entry\0" if "--stage" in command else b""
        return subprocess.CompletedProcess(command, 0, output, b"")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Git mode"):
        module._publication_files(root)


def test_publication_inventory_rejects_filesystem_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches following a filesystem link and hashing its target bytes."""
    root = tmp_path / "publication"
    root.mkdir()
    candidate = root / "linked-entry"
    candidate.write_text("safe", encoding="utf-8")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == candidate or original(path))

    with pytest.raises(ValueError, match="non-symlink"):
        load_validator()._publication_files(root)


def test_publication_inventory_rejects_reparse_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches a Windows reparse point that does not present as a normal symlink."""
    root = tmp_path / "publication"
    root.mkdir()
    candidate = root / "reparse-entry"
    candidate.write_text("safe", encoding="utf-8")
    original = Path.lstat
    metadata = candidate.lstat()

    def fake_lstat(path: Path) -> object:
        if path == candidate:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return original(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(ValueError, match="reparse"):
        load_validator()._publication_files(root)


def test_publication_inventory_rejects_resolved_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches a regular lexical child resolving through a linked parent outside the root."""
    root = tmp_path / "publication"
    root.mkdir()
    candidate = root / "escaped-entry"
    candidate.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside-entry"
    outside.write_text("private", encoding="utf-8")
    original = Path.resolve

    def fake_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        if path == candidate:
            return outside
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    with pytest.raises(ValueError, match="escapes publication root"):
        load_validator()._publication_files(root)
