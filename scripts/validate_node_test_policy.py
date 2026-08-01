"""Validate the protected-base Node test manifest against the candidate head."""

from __future__ import annotations

import argparse
import pathlib

from verify_runtime_evidence import load_node_policy_from_base


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--base-sha", required=True)
    args = parser.parse_args()
    load_node_policy_from_base(args.root.resolve(), args.base_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
