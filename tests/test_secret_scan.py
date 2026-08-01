from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "secret_scan.py"


def load_scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("secret_scan", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_config(path: Path, *, max_file_bytes: int = 128) -> str:
    payload = (
        json.dumps(
            {
                "schema_version": 1,
                "tool_version": "1.0.0",
                "max_file_bytes": max_file_bytes,
                "patterns": [{"name": "synthetic-token", "regex": "TOKEN_[A-Z]{8}"}],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    path.write_bytes(payload)
    return hashlib.sha256(
        json.dumps(json.loads(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def test_secret_scan_positive_negative_and_oversize_are_fail_closed(tmp_path: Path) -> None:
    """Catches a large tracked file bypassing the bounded high-confidence scan."""
    module = load_scanner()
    config = tmp_path / "config.json"
    digest = write_config(config)
    config.write_bytes(config.read_bytes().replace(b"\n", b"\r\n"))
    module.load_config(config, digest)
    clean = tmp_path / "clean.txt"
    secret = tmp_path / "secret.txt"
    oversized = tmp_path / "oversized.txt"
    clean.write_text("ordinary text", encoding="utf-8")
    secret.write_text("TOKEN_ABCDEFGH", encoding="utf-8")
    oversized.write_bytes(b"x" * 129)

    assert (
        module.scan(
            tmp_path,
            config=config,
            expected_config_sha256=digest,
            paths=[clean],
        )
        == []
    )
    assert module.scan(
        tmp_path,
        config=config,
        expected_config_sha256=digest,
        paths=[secret],
    ) == [("secret.txt", "synthetic-token")]
    assert module.scan(
        tmp_path,
        config=config,
        expected_config_sha256=digest,
        paths=[oversized],
    ) == [("oversized.txt", "oversize-unscanned")]


def test_tracked_non_utf8_binary_and_utf16_secrets_cannot_bypass_scan(tmp_path: Path) -> None:
    """Catches tracked byte encodings that strict UTF-8 text reads would skip or obscure."""
    module = load_scanner()
    config = tmp_path / "config.json"
    digest = write_config(config)
    canaries = {
        "binary.dat": b"\x00\x01TOKEN_ABCDEFGH\x00\xff",
        "mixed-invalid-utf8.bin": b"header \xf0(\x8c( TOKEN_ABCDEFGH \xff trailer",
        "utf16-be.txt": "prefix TOKEN_ABCDEFGH suffix".encode("utf-16-be"),
        "utf16-be-with-binary-prefix.bin": b"\xff" + "TOKEN_ABCDEFGH".encode("utf-16-be"),
        "utf16-le.txt": "prefix TOKEN_ABCDEFGH suffix".encode("utf-16-le"),
        "utf16-le-with-binary-prefix.bin": b"\xff" + "TOKEN_ABCDEFGH".encode("utf-16-le"),
    }
    for name, payload in canaries.items():
        (tmp_path / name).write_bytes(payload)

    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", *canaries], cwd=tmp_path, check=True)

    assert module.scan(
        tmp_path,
        config=config,
        expected_config_sha256=digest,
    ) == [
        ("binary.dat", "synthetic-token"),
        ("mixed-invalid-utf8.bin", "synthetic-token"),
        ("utf16-be-with-binary-prefix.bin", "synthetic-token"),
        ("utf16-be.txt", "synthetic-token"),
        ("utf16-le-with-binary-prefix.bin", "synthetic-token"),
        ("utf16-le.txt", "synthetic-token"),
    ]


def test_public_negative_canary_is_safe_at_rest_and_detected_only_after_composition(tmp_path: Path) -> None:
    """Catches reintroducing a push-protection-shaped credential into a tracked canary file."""
    module = load_scanner()
    contract = json.loads((ROOT / "contract" / "v1.json").read_text(encoding="utf-8"))
    security = contract["x-merge-gate-v1"]["common_security"]
    config = ROOT / security["config"]
    parts = [ROOT / relative for relative in security["negative_canary_parts"]]

    for part in parts:
        assert (
            module.scan(
                ROOT,
                config=config,
                expected_config_sha256=security["config_sha256"],
                paths=[part],
            )
            == []
        )

    composed = tmp_path / "composed.txt"
    composed.write_bytes(b"".join(part.read_bytes().strip() for part in parts))
    assert module.scan(
        tmp_path,
        config=config,
        expected_config_sha256=security["config_sha256"],
        paths=[composed],
    ) == [("composed.txt", "github-token")]


@pytest.mark.parametrize("absolute", [False, True])
def test_secret_scan_rejects_relative_and_absolute_file_symlinks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    absolute: bool,
) -> None:
    """Catches a target path redirecting the scanner to bytes outside the checkout."""
    module = load_scanner()
    root = tmp_path / "checkout"
    root.mkdir()
    outside = tmp_path / "runner-secret.txt"
    outside.write_text("TOKEN_ABCDEFGH", encoding="utf-8")
    config = tmp_path / "config.json"
    digest = write_config(config)
    link = root / "linked.txt"
    link.write_text(str(outside if absolute else Path("..") / outside.name), encoding="utf-8")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == link or original_is_symlink(self),
    )

    with pytest.raises(ValueError, match="non-symlink"):
        module.scan(
            root,
            config=config,
            expected_config_sha256=digest,
            paths=[link],
        )
