#!/usr/bin/env bash
set -u

artifacts_parent="${CI_PLATFORM_TEST_ARTIFACTS_DIR:-${TMPDIR:-/tmp}}"
temporary_root=""
status=1

cleanup() {
  if [ -n "$temporary_root" ]; then
    rm -rf -- "$temporary_root" || :
  fi
}
trap cleanup EXIT

if ! mkdir -p -- "$artifacts_parent"; then
  exit 1
fi
if ! temporary_root="$(mktemp -d "$artifacts_parent/ci-platform-pytest.XXXXXX")"; then
  exit 1
fi

python_bin="${PYTHON:-python3}"
set +e
"$python_bin" -B -m pytest "$@" -p no:cacheprovider \
  "--basetemp=$temporary_root/basetemp" \
  "--junitxml=$temporary_root/pytest-junit.xml"
status=$?
exit "$status"
