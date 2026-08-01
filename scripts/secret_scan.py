"""Pinned, read-only high-confidence secret scanner for untrusted repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_config_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def load_config(path: Path, expected_sha256: str) -> tuple[int, list[tuple[str, re.Pattern[str]]]]:
    if not SHA256.fullmatch(expected_sha256):
        raise ValueError("expected secret-scan config SHA-256 is malformed")
    payload = path.read_bytes()
    value = json.loads(payload)
    if canonical_config_sha256(value) != expected_sha256:
        raise ValueError("secret-scan canonical config digest does not match the pinned contract")
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "tool_version",
        "max_file_bytes",
        "patterns",
    }:
        raise ValueError("secret-scan config shape is invalid")
    if value["schema_version"] != 1 or value["tool_version"] != "1.0.0":
        raise ValueError("secret-scan tool/config version is unsupported")
    max_bytes = value["max_file_bytes"]
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 10_000_000:
        raise ValueError("secret-scan max_file_bytes is invalid")
    patterns = value["patterns"]
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("secret-scan pattern inventory is empty")
    compiled: list[tuple[str, re.Pattern[str]]] = []
    names: set[str] = set()
    for entry in patterns:
        if not isinstance(entry, dict) or set(entry) != {"name", "regex"}:
            raise ValueError("secret-scan pattern is malformed")
        name, expression = entry["name"], entry["regex"]
        if not isinstance(name, str) or not name or name in names or not isinstance(expression, str):
            raise ValueError("secret-scan pattern identity is invalid")
        names.add(name)
        compiled.append((name, re.compile(expression, flags=re.ASCII)))
    return max_bytes, compiled


def _tracked_paths(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=60,
    )
    return [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def _lossless_content_views(content: bytes) -> tuple[str, ...]:
    """Expose raw bytes and both UTF-16 code-unit orders without dropping input."""
    views = [content.decode("latin-1")]
    for offset in range(2):
        aligned = content[offset:]
        complete_code_units = aligned[: len(aligned) - (len(aligned) % 2)]
        if complete_code_units:
            views.extend(
                complete_code_units.decode(encoding, errors="surrogatepass") for encoding in ("utf-16-le", "utf-16-be")
            )
    return tuple(views)


def scan(
    root: Path,
    *,
    config: Path,
    expected_config_sha256: str,
    paths: list[Path] | None = None,
) -> list[tuple[str, str]]:
    """Return redacted ``(relative path, rule name)`` findings."""
    root = root.resolve()
    max_bytes, patterns = load_config(config, expected_config_sha256)
    candidates = paths if paths is not None else _tracked_paths(root)
    findings: list[tuple[str, str]] = []
    for candidate in candidates:
        lexical = candidate if candidate.is_absolute() else root / candidate
        try:
            lexical.relative_to(root)
            metadata = lexical.lstat()
        except (OSError, ValueError) as error:
            raise ValueError("secret-scan path is unavailable or escapes repository root") from error
        if lexical.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("secret-scan path is not a regular non-symlink file")
        path = lexical.resolve(strict=True)
        if root != path and root not in path.parents:
            raise ValueError("secret-scan path escapes repository root")
        relative = lexical.relative_to(root).as_posix()
        if metadata.st_size > max_bytes:
            findings.append((relative, "oversize-unscanned"))
            continue
        content_views = _lossless_content_views(path.read_bytes())
        for name, pattern in patterns:
            if any(pattern.search(content) for content in content_views):
                findings.append((relative, name))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--path", type=Path, action="append")
    args = parser.parse_args()
    try:
        findings = scan(
            args.root,
            config=args.config,
            expected_config_sha256=args.expected_config_sha256,
            paths=args.path,
        )
    except (OSError, ValueError, json.JSONDecodeError, re.error, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if findings:
        print("high-confidence secret material detected:", file=sys.stderr)
        for relative, rule in findings:
            print(f"{relative}: {rule}", file=sys.stderr)
        return 2
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
