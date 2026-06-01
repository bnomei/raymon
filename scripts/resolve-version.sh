#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_REF_NAME:-}" == v* ]]; then
  version="${GITHUB_REF_NAME#v}"
else
  version=$(python - <<'PY'
import json
import subprocess

meta = json.loads(
    subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"])
)
print(meta["packages"][0]["version"])
PY
  )
fi

numeric_identifier='(0|[1-9][0-9]*)'
prerelease_identifier='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
build_identifier='[0-9A-Za-z-]+'
semver_regex="^${numeric_identifier}[.]${numeric_identifier}[.]${numeric_identifier}(-${prerelease_identifier}([.]${prerelease_identifier})*)?([+]${build_identifier}([.]${build_identifier})*)?$"
if [[ ! "$version" =~ $semver_regex ]]; then
  echo "ref resolved to an invalid semver version: $version" >&2
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=${version}" >> "$GITHUB_OUTPUT"
else
  echo "$version"
fi
