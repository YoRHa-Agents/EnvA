#!/usr/bin/env bash
set -euo pipefail

BINARY_PATH="${1:-${ENVA_INSTALLED_BINARY:-${RWC_INSTALLED_BINARY:-}}}"

if [[ -z "${BINARY_PATH}" ]]; then
  echo "error: missing installed Enva binary path" >&2
  echo "pass the binary path as the first argument or set ENVA_INSTALLED_BINARY / RWC_INSTALLED_BINARY" >&2
  exit 1
fi

if [[ ! -x "${BINARY_PATH}" ]]; then
  echo "error: installed Enva binary is not executable: ${BINARY_PATH}" >&2
  exit 1
fi

echo "Running Enva post-install smoke with ${BINARY_PATH}"
"${BINARY_PATH}" vault self-test
"${BINARY_PATH}" update --help >/dev/null
echo "Enva post-install smoke passed"
