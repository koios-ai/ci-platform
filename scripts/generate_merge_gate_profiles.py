"""Generate immutable profile-specific merge-gate workflow source files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROFILE_WORKFLOWS = {
    "baseline": "merge-gate-v1.yml",
    "python": "merge-gate-python-v1.yml",
    "node": "merge-gate-node-v1.yml",
    "powershell": "merge-gate-powershell-v1.yml",
    "critical-ml": "merge-gate-critical-ml-v1.yml",
}
SOURCE_REPOSITORY = "koios-ai/ci-platform"
SOURCE_JOB_GUARD = f"github.repository != '{SOURCE_REPOSITORY}'"
PROFILE_WORKFLOW_NAMES = {profile: f"Koios CI / merge gate / {profile}" for profile in PROFILE_WORKFLOWS}
PROFILE_MARKERS = (
    f"name: {PROFILE_WORKFLOW_NAMES['baseline']}",
    "  CI_PLATFORM_PROFILE: baseline",
    "  group: merge-gate-v1-baseline-",
)


def generated_workflows(root: Path) -> dict[Path, str]:
    source_path = root / ".github" / "workflows" / PROFILE_WORKFLOWS["baseline"]
    source = source_path.read_text(encoding="utf-8")
    if any(source.count(marker) != 1 for marker in PROFILE_MARKERS):
        raise ValueError("baseline workflow must contain each immutable profile marker once")
    directory = source_path.parent
    generated: dict[Path, str] = {}
    for profile, workflow in PROFILE_WORKFLOWS.items():
        if profile == "baseline":
            continue
        profile_source = (
            source.replace(
                PROFILE_MARKERS[0],
                f"name: {PROFILE_WORKFLOW_NAMES[profile]}",
                1,
            )
            .replace(
                PROFILE_MARKERS[1],
                f"  CI_PLATFORM_PROFILE: {profile}",
                1,
            )
            .replace(
                PROFILE_MARKERS[2],
                f"  group: merge-gate-v1-{profile}-",
                1,
            )
        )
        generated[directory / workflow] = profile_source
    return generated


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        generated = generated_workflows(args.root)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    drift: list[str] = []
    for path, expected in generated.items():
        if args.write:
            path.write_text(expected, encoding="utf-8", newline="\n")
        elif not path.is_file() or path.read_text(encoding="utf-8") != expected:
            drift.append(str(path.relative_to(args.root)))
    if drift:
        print("generated merge-gate workflow drift: " + ", ".join(drift), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
