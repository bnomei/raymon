#!/usr/bin/env bash
set -euo pipefail

bench_target="${1:-raymon_perf}"
ts="$(date +"%Y%m%d-%H%M%S")"
out_root="${DIVAN_OUT_DIR:-benchmarks/results}"
out_dir="${out_root}/${ts}"

mkdir -p "${out_dir}"

export RUSTFLAGS="${RUSTFLAGS:-} -Awarnings"

bench_targets=()
if [[ "${bench_target}" == "all" ]]; then
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    bench_targets+=("${name}")
  done < <(
    python3 - <<'PY'
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # py3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

data = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))
for bench in data.get("bench", []):
    name = bench.get("name")
    if name:
        print(name)
PY
  )
else
  bench_targets+=("${bench_target}")
fi

meta_file="${out_dir}/_meta.txt"
{
  echo "timestamp=${ts}"
  echo "bench_targets=${bench_targets[*]}"
  echo "git_rev=$(git rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
} > "${meta_file}"

echo "Divan results: ${out_dir}"
echo "Metadata: ${meta_file}"

for target in "${bench_targets[@]}"; do
  bench_list="$(
    NEXTEST=1 cargo bench -q --bench "${target}" -- --list --format terse \
      | sed -n 's/: benchmark$//p'
  )"

  if [[ -z "${bench_list}" ]]; then
    echo "No benchmarks found for bench target '${target}'" >&2
    exit 1
  fi

  while IFS= read -r bench_name; do
    [[ -z "${bench_name}" ]] && continue

    # Sanitize bench name for filesystem paths.
    file_base="$(printf '%s' "${bench_name}" | sed 's/[^A-Za-z0-9_.-]/_/g')"
    out_file="${out_dir}/${file_base}.txt"

    echo "==> ${bench_name}"
    (cargo bench -q --bench "${target}" -- --exact "${bench_name}" --color never) 2>&1 | tee "${out_file}"
  done <<< "${bench_list}"
done
