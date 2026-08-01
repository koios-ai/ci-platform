"""Validate the protected-base test-policy manifest without executing consumer tests."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from test_policy import load_policy_from_base, validate_profile_policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--profile", choices=("python", "critical-ml"), required=True)
    args = parser.parse_args()
    try:
        policy, digest = load_policy_from_base(pathlib.Path.cwd(), args.base_sha)
        validate_profile_policy(policy, args.profile)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "critical_categories": sorted(policy["critical_tests"]) if args.profile == "critical-ml" else [],
                "policy_digest": digest,
                "profile": args.profile,
                "status": "validated",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
