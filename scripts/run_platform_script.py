"""Launch one immutable platform script under ``python -I -S``."""

from __future__ import annotations

import argparse
import pathlib
import runpy
import sys

ALLOWED_SCRIPTS = {"run_test_policy"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform-root", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-site", type=pathlib.Path, required=True)
    parser.add_argument("--script", choices=sorted(ALLOWED_SCRIPTS), required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    platform_root = args.platform_root.resolve()
    trusted_site = args.trusted_site.resolve()
    scripts = platform_root / "scripts"
    script = scripts / f"{args.script}.py"
    if not scripts.is_dir() or not trusted_site.is_dir() or not script.is_file():
        raise ValueError("immutable platform runtime paths are unavailable")
    sys.path[:0] = [str(scripts), str(trusted_site)]
    forwarded = list(args.arguments)
    if forwarded[:1] == ["--"]:
        forwarded.pop(0)
    sys.argv = [str(script), *forwarded]
    runpy.run_path(str(script), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
