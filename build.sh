#!/usr/bin/env bash
# Build release binaries for supported platforms into ./release/
# Artifact names match scripts/install.sh (enva-linux-x86_64, etc.).
#
# Usage:
#   ./build.sh [options] [platform ...]
#
#   platform (one or more, or omit for all):
#     all              — linux-x86_64, linux-aarch64, macos-aarch64
#     linux-x86_64     — x86_64-unknown-linux-gnu
#     linux-aarch64    — aarch64-unknown-linux-gnu
#     macos-aarch64    — aarch64-apple-darwin
#
#   Options:
#     --clean     cargo clean, remove release/, then build
#     --list      print known platforms and exit
#     --serial    build one at a time (default when a single platform is given)
#     -h, --help
#
#   With multiple platforms (or `all`), builds run in parallel; each job uses its
#   own CARGO_TARGET_DIR. Live cargo output is in target/px/logs/<artifact>.log
#
# Dependencies:
#   - rustup + stable toolchain
#   - Cross targets: zig + cargo install cargo-zigbuild

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BAR_WIDTH="${BAR_WIDTH:-28}"

usage() {
  sed -n '2,/^# Dependencies:/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
  exit 0
}

# label|triple|artifact
PLATFORM_ROWS=(
  "linux-x86_64|x86_64-unknown-linux-gnu|enva-linux-x86_64"
  "linux-aarch64|aarch64-unknown-linux-gnu|enva-linux-aarch64"
  "macos-aarch64|aarch64-apple-darwin|enva-macos-aarch64"
)

list_platforms() {
  echo "Platforms (use as ./build.sh <name> [...]):"
  for row in "${PLATFORM_ROWS[@]}"; do
    IFS='|' read -r label triple artifact <<<"${row}"
    printf '  %-16s  %s  -> release/%s\n' "${label}" "${triple}" "${artifact}"
  done
}

resolve_rows() {
  local -a names=("$@")
  local -a out=()
  local n found
  if [[ ${#names[@]} -eq 0 ]] || [[ "${names[0]}" == "all" && ${#names[@]} -eq 1 ]]; then
    printf '%s\n' "${PLATFORM_ROWS[@]}"
    return
  fi
  for n in "${names[@]}"; do
    found=
    for row in "${PLATFORM_ROWS[@]}"; do
      IFS='|' read -r label triple artifact <<<"${row}"
      if [[ "${n}" == "${label}" || "${n}" == "${triple}" || "${n}" == "${artifact}" ]]; then
        out+=("${row}")
        found=1
        break
      fi
    done
    if [[ -z "${found}" ]]; then
      echo "error: unknown platform '${n}' (try --list)" >&2
      exit 1
    fi
  done
  local -a deduped=()
  local row x exists
  for row in "${out[@]}"; do
    exists=
    for x in "${deduped[@]}"; do
      if [[ "${x}" == "${row}" ]]; then
        exists=1
        break
      fi
    done
    if [[ -n "${exists}" ]]; then
      continue
    fi
    deduped+=("${row}")
  done
  for row in "${deduped[@]}"; do
    printf '%s\n' "${row}"
  done
}

CLEAN=false
SERIAL=false
declare -a USER_PLATFORMS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      CLEAN=true
      shift
      ;;
    --list)
      list_platforms
      exit 0
      ;;
    --serial)
      SERIAL=true
      shift
      ;;
    -h | --help)
      usage
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1 (try --help)" >&2
      exit 1
      ;;
    *)
      USER_PLATFORMS+=("$1")
      shift
      ;;
  esac
done

if $CLEAN; then
  cargo clean
  rm -rf release
fi

mkdir -p release

host_triple="$(rustc -vV | sed -n 's/^host: //p')"

need_zig_for_cross() {
  local target="$1"
  if ! command -v zig >/dev/null 2>&1; then
    echo "error: cross-compiling to ${target} requires zig in PATH" >&2
    echo "  https://ziglang.org/download/" >&2
    exit 1
  fi
  if ! cargo zigbuild --help >/dev/null 2>&1; then
    echo "error: install cargo-zigbuild: cargo install cargo-zigbuild" >&2
    exit 1
  fi
}

preflight_targets() {
  local triple
  for triple in "$@"; do
    if [[ "${triple}" != "${host_triple}" ]]; then
      need_zig_for_cross "${triple}"
    fi
  done
}

# args: completed total [status_line]
draw_progress_bar() {
  local done="$1"
  local total="$2"
  local extra="${3:-}"
  local width="${BAR_WIDTH}"
  if ((total <= 0)); then
    printf '\r\033[K%s' "${extra}" >&2
    return
  fi
  local filled=$((done * width / total))
  local pct=$((done * 100 / total))
  local i
  local bar=""
  for ((i = 0; i < width; i++)); do
    if ((i < filled)); then
      bar+="#"
    else
      bar+="-"
    fi
  done
  printf '\r\033[K[%s] %3d%% %d/%d %s' "${bar}" "${pct}" "${done}" "${total}" "${extra}" >&2
}

progress_finish() {
  printf '\n' >&2
}

# Run inside subshell: env TRIPLE ARTIFACT LABEL PXDIR HOST_TRIPLE ROOT
build_job() {
  set -euo pipefail
  cd "${ROOT}"
  export CARGO_TARGET_DIR="${PXDIR}"
  mkdir -p "${CARGO_TARGET_DIR}"

  if [[ "${TRIPLE}" == "aarch64-apple-darwin" ]]; then
    local shim_dir="${ROOT}/tools/apple-sdk-shim"
    local triple_env="${TRIPLE//-/_}"
    export "CFLAGS_${triple_env}=-I${shim_dir}"
    export "CPPFLAGS_${triple_env}=-I${shim_dir}"
  fi

  rustup target add "${TRIPLE}" >/dev/null 2>&1 || rustup target add "${TRIPLE}"

  if [[ "${TRIPLE}" == "${HOST_TRIPLE}" ]]; then
    cargo build --release -p enva --target "${TRIPLE}"
  else
    cargo zigbuild --release -p enva --target "${TRIPLE}"
  fi

  local bin="${CARGO_TARGET_DIR}/${TRIPLE}/release/enva"
  if [[ ! -f "${bin}" ]]; then
    echo "error: expected binary missing: ${bin}" >&2
    exit 1
  fi
  cp "${bin}" "${ROOT}/release/${ARTIFACT}"
  chmod +x "${ROOT}/release/${ARTIFACT}"
}

run_serial() {
  local rows_csv="$1"
  local row label triple artifact pxdir logf
  local i=0 total
  total="$(echo "${rows_csv}" | grep -c . || true)"
  [[ -z "${total}" || "${total}" -eq 0 ]] && return

  while IFS= read -r row; do
    [[ -z "${row}" ]] && continue
    IFS='|' read -r label triple artifact <<<"${row}"
    pxdir="${ROOT}/target/px/${artifact}"
    mkdir -p "${ROOT}/target/px/logs"
    logf="${ROOT}/target/px/logs/${artifact}.log"
    preflight_targets "${triple}"
    ((i++)) || true
    draw_progress_bar $((i - 1)) "${total}" "${label} (starting...)"
    export TRIPLE="${triple}" ARTIFACT="${artifact}" LABEL="${label}" PXDIR="${pxdir}" HOST_TRIPLE="${host_triple}" ROOT="${ROOT}"
    if build_job >"${logf}" 2>&1; then
      draw_progress_bar "${i}" "${total}" "${label} ok"
    else
      draw_progress_bar "${i}" "${total}" "${label} FAILED"
      progress_finish
      echo "error: build failed for ${label}; see ${logf}" >&2
      tail -n 40 "${logf}" >&2
      exit 1
    fi
  done <<<"${rows_csv}"
  progress_finish
  while IFS= read -r row; do
    [[ -z "${row}" ]] && continue
    IFS='|' read -r _ _ artifact <<<"${row}"
    echo "  -> release/${artifact}"
  done <<<"${rows_csv}"
}

run_parallel() {
  local rows_csv="$1"
  declare -a pids=()
  declare -a labels=()
  declare -a artifacts=()
  declare -a triples=()
  local row label triple artifact pxdir logf

  while IFS= read -r row; do
    [[ -z "${row}" ]] && continue
    IFS='|' read -r label triple artifact <<<"${row}"
    triples+=("${triple}")
    labels+=("${label}")
    artifacts+=("${artifact}")
  done <<<"${rows_csv}"

  preflight_targets "${triples[@]}"

  local n="${#labels[@]}"
  if [[ "${n}" -eq 0 ]]; then
    return
  fi

  mkdir -p "${ROOT}/target/px/logs"

  local idx
  for ((idx = 0; idx < n; idx++)); do
    label="${labels[idx]}"
    triple="${triples[idx]}"
    artifact="${artifacts[idx]}"
    pxdir="${ROOT}/target/px/${artifact}"
    logf="${ROOT}/target/px/logs/${artifact}.log"
    (
      export TRIPLE="${triple}" ARTIFACT="${artifact}" LABEL="${label}" PXDIR="${pxdir}" HOST_TRIPLE="${host_triple}" ROOT="${ROOT}"
      build_job >"${logf}" 2>&1
    ) &
    pids+=($!)
  done

  declare -a alive=("${pids[@]}")
  local completed=0
  local failed=0

  draw_progress_bar 0 "${n}" "starting ${n} jobs..."

  while ((${#alive[@]} > 0)); do
    declare -a next=()
    for pid in "${alive[@]}"; do
      if kill -0 "${pid}" 2>/dev/null; then
        next+=("${pid}")
      else
        if ! wait "${pid}"; then
          failed=1
        fi
        ((completed++)) || true
        draw_progress_bar "${completed}" "${n}" "done ${completed}, running $((n - completed))..."
      fi
    done
    alive=("${next[@]}")
    ((${#alive[@]} > 0)) && sleep 0.2
  done

  progress_finish

  if [[ "${failed}" -ne 0 ]]; then
    echo "error: one or more parallel builds failed. Logs:" >&2
    for ((idx = 0; idx < n; idx++)); do
      logf="${ROOT}/target/px/logs/${artifacts[idx]}.log"
      echo "--- ${labels[idx]} (${logf}) ---" >&2
      tail -n 25 "${logf}" >&2
    done
    exit 1
  fi

  for ((idx = 0; idx < n; idx++)); do
    echo "  -> release/${artifacts[idx]}"
  done
}

ROWS_CSV_TMP="$(resolve_rows "${USER_PLATFORMS[@]}")"
ROWS=()
while IFS= read -r line || [[ -n "${line}" ]]; do
  if [[ -n "${line}" ]]; then
    ROWS+=("${line}")
  fi
done <<<"${ROWS_CSV_TMP}"
ROWS_CSV=$(printf '%s\n' "${ROWS[@]}")

count="${#ROWS[@]}"
if [[ "${count}" -eq 0 ]]; then
  echo "error: no platforms selected" >&2
  exit 1
fi

echo "Host: ${host_triple}"
echo "Building enva (${count} platform(s))..."

if [[ "${count}" -eq 1 ]] || $SERIAL; then
  run_serial "${ROWS_CSV}"
else
  run_parallel "${ROWS_CSV}"
fi

echo "Done. Outputs:"
ls -la release/
