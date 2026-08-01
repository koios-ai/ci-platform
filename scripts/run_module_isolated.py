"""Run one pinned platform tool without site startup or target import paths."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import runpy
import sys

ALLOWED_MODULES = {"bandit", "mypy", "pip_audit", "ruff"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-site", type=pathlib.Path, required=True)
    parser.add_argument("--module", choices=sorted(ALLOWED_MODULES), required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    trusted_site = args.trusted_site.resolve()
    if not trusted_site.is_dir():
        raise ValueError("trusted platform site-packages path is unavailable")
    arguments = list(args.arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    sys.path.insert(0, str(trusted_site))
    spec = importlib.util.find_spec(args.module)
    if spec is None or spec.origin is None or trusted_site not in pathlib.Path(spec.origin).resolve().parents:
        raise ValueError("platform tool did not resolve from trusted site-packages")
    sys.argv = [args.module, *arguments]
    runpy.run_module(args.module, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
