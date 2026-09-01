#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version, e.g. 1.4.2>" >&2
  exit 2
fi

version="${1#v}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid semantic version: $1" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT VERSION="$version"

python3 <<'PY'
import datetime
import json
import os
import pathlib
import re

root = pathlib.Path(os.environ["ROOT"])
version = os.environ["VERSION"]
tag = f"v{version}"

def replace(path, pattern, replacement, count=0):
    text = path.read_text()
    updated, changed = re.subn(pattern, replacement, text, count=count)
    if not changed:
        raise SystemExit(f"version marker not found in {path}")
    path.write_text(updated)

replace(root / "Cargo.toml", r'(?m)^version = "[^"]+"$', f'version = "{version}"', 1)
replace(root / "site/index.html", r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?', tag, 1)
replace(root / "site/demo.html", r'enva [0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?', f'enva {version}', 1)
replace(root / "crates/enva/web/index.html", r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?', tag)

for path in sorted((root / "npm").glob("*/package.json")):
    package = json.loads(path.read_text())
    package["version"] = version
    if path.parent.name == "enva":
        package["optionalDependencies"] = {
            name: version for name in package["optionalDependencies"]
        }
    path.write_text(json.dumps(package, indent=2) + "\n")

changelog = root / "CHANGELOG.md"
content = changelog.read_text()
if f"## [{version}]" not in content:
    today = datetime.date.today().isoformat()
    entry = f"## [{version}] - {today}\n\n- Release preparation.\n\n"
    # Keep a Changelog ordering: the new section belongs directly below
    # [Unreleased], not above the file's introductory prose.
    marker = "## [Unreleased]\n"
    if marker not in content:
        raise SystemExit("CHANGELOG.md is missing its [Unreleased] section")
    content = content.replace(marker, marker + "\n" + entry, 1)
    changelog.write_text(content)

print(f"Updated release surfaces to {version}.")
PY
