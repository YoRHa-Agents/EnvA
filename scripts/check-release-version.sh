#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi

tag="${1#v}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT EXPECTED_VERSION="$tag"

python3 <<'PY'
import os
import pathlib
import re

root = pathlib.Path(os.environ["ROOT"])
expected = os.environ["EXPECTED_VERSION"]

manifest = (root / "Cargo.toml").read_text()
match = re.search(r'(?m)^version = "([^"]+)"$', manifest)
if not match or match.group(1) != expected:
    raise SystemExit(f"Cargo.toml version is {match.group(1) if match else 'missing'}, expected {expected}")

changelog = (root / "CHANGELOG.md").read_text()
if f"## [{expected}]" not in changelog:
    raise SystemExit(f"CHANGELOG.md has no entry for {expected}")

print(f"Release version check passed: v{expected}")
PY
