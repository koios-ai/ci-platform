"""Reconstruct the changed-file evidence from an exact local checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from merge_gate_policy import SHA, git_changed_files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--fast-output", type=Path)
    outputs.add_argument("--verify-digest")
    args = parser.parse_args()
    if not SHA.fullmatch(args.base) or not SHA.fullmatch(args.head):
        raise ValueError("changed-file evidence requires full commit identities")
    actual_head = subprocess.check_output(
        ["git", "--no-replace-objects", "rev-parse", "--verify", "HEAD"], cwd=args.root, timeout=5, text=True
    )
    if actual_head.strip() != args.head:
        raise ValueError("target checkout is not the exact event head")
    paths = git_changed_files(args.root, args.base, args.head)
    digest = hashlib.sha256("".join(f"{path}\n" for path in paths).encode("utf-8")).hexdigest()
    if args.verify_digest is not None and digest != args.verify_digest:
        raise ValueError("changed-file digest does not match the checked-out commits")

    python_paths = []
    if args.fast_output is not None:
        for relative in paths:
            path = args.root / relative
            if path.is_symlink():
                raise ValueError("changed path is a symbolic link")
            if relative.endswith(".py") and path.is_file():
                python_paths.append(f"./{relative}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(paths, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.fast_output is not None:
        python_changes = any(path.endswith(".py") for path in paths)
        with args.fast_output.open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"changed_files_digest={digest}\n")
            output.write(f"has_python={str(bool(python_paths)).lower()}\n")
            output.write(f"has_python_changes={str(python_changes).lower()}\n")
            output.write(f"python_paths={json.dumps(python_paths, separators=(',', ':'))}\n")


if __name__ == "__main__":
    main()
