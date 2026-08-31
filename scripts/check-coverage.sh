#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

threshold_file="${COVERAGE_THRESHOLDS_FILE:-$ROOT/.coverage-thresholds}"
output_dir="${COVERAGE_OUTPUT_DIR:-$ROOT/target/coverage}"
baseline=false
if [[ "${1:-}" == "--baseline" ]]; then
  baseline=true
fi

mkdir -p "$output_dir"

extract_percent() {
  awk '
    /TOTAL/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+([.][0-9]+)?%$/) {
          value = $i
        }
      }
    }
    END {
      if (value == "") exit 1
      sub("%", "", value)
      print value
    }
  ' "$1"
}

global_report="$output_dir/global-summary.txt"
core_report="$output_dir/enva-core-summary.txt"

cargo llvm-cov --workspace --all-targets \
  --lcov --output-path "$output_dir/lcov.info" >/dev/null
cargo llvm-cov --workspace --all-targets --summary-only 2>&1 | tee "$global_report"
cargo llvm-cov -p enva-core --all-targets --summary-only 2>&1 | tee "$core_report"

global_actual="$(extract_percent "$global_report")"
core_actual="$(extract_percent "$core_report")"

if "$baseline"; then
  global_floor="$(awk -v value="$global_actual" 'BEGIN { floor = int(value) - 2; if (floor < 0) floor = 0; print floor }')"
  core_floor="$(awk -v value="$core_actual" 'BEGIN { floor = int(value); if (floor < 0) floor = 0; print floor }')"
  {
    printf '# Generated from cargo llvm-cov baseline; review when coverage scope changes.\n'
    printf 'global_lines=%s\n' "$global_floor"
    printf 'enva_core_lines=%s\n' "$core_floor"
  } > "$threshold_file"
  echo "Wrote coverage floors to $threshold_file"
  exit 0
fi

if [[ ! -f "$threshold_file" ]]; then
  echo "Coverage threshold file is missing: $threshold_file" >&2
  echo "Run ./scripts/check-coverage.sh --baseline and commit the reviewed result." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$threshold_file"

awk -v actual="$global_actual" -v floor="$global_lines" \
  'BEGIN { if (actual + 0 < floor + 0) exit 1 }' || {
  echo "Global line coverage ${global_actual}% is below ${global_lines}%." >&2
  exit 1
}
awk -v actual="$core_actual" -v floor="$enva_core_lines" \
  'BEGIN { if (actual + 0 < floor + 0) exit 1 }' || {
  echo "enva-core line coverage ${core_actual}% is below ${enva_core_lines}%." >&2
  exit 1
}

printf 'Coverage floors passed: global %s%% >= %s%%; enva-core %s%% >= %s%%\n' \
  "$global_actual" "$global_lines" "$core_actual" "$enva_core_lines"
