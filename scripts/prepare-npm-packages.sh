#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <release-directory> <output-directory>" >&2
  exit 2
fi

version="${1#v}"
release_dir="$2"
output_dir="$3"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf "$output_dir"
mkdir -p "$output_dir"

declare -A assets=(
  [enva-linux-x64]=enva-linux-x86_64
  [enva-linux-arm64]=enva-linux-aarch64
  [enva-darwin-arm64]=enva-macos-aarch64
)

for package in enva enva-linux-x64 enva-linux-arm64 enva-darwin-arm64; do
  source_dir="$ROOT/npm/$package"
  destination="$output_dir/$package"
  mkdir -p "$destination"
  cp "$source_dir/package.json" "$destination/package.json"
  if [[ "$package" == "enva" ]]; then
    mkdir -p "$destination/bin"
    cp "$source_dir/bin/enva.js" "$destination/bin/enva.js"
    continue
  fi
  mkdir -p "$destination/bin"
  asset="${assets[$package]}"
  if [[ ! -f "$release_dir/$asset" ]]; then
    echo "missing release asset: $release_dir/$asset" >&2
    exit 1
  fi
  cp "$release_dir/$asset" "$destination/bin/enva"
  chmod +x "$destination/bin/enva"
done

python3 - "$output_dir" "$version" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
version = sys.argv[2]
for path in root.glob("*/package.json"):
    package = json.loads(path.read_text())
    if package["version"] != version:
        raise SystemExit(f"{path} has version {package['version']}, expected {version}")
    if path.parent.name == "enva":
        for dependency_version in package["optionalDependencies"].values():
            if dependency_version != version:
                raise SystemExit(f"{path} has an out-of-sync optional dependency")
print(f"Prepared npm packages in {root}")
PY
