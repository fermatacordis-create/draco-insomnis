#!/usr/bin/env bash
# Builds the Python package from python/: a wheel and a source archive. No dependencies at run time;
# the build needs the "build" module (pip install build), which fetches setuptools in isolation.
# Usage: bin/build-python.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r python "$tmp/python"
cp LICENSE "$tmp/python/LICENSE"
find "$tmp/python" \( -name __pycache__ -o -name '*.egg-info' -o -name build \) -prune -exec rm -rf {} +
# The commit's time in the archives, so the same commit builds the same files.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
python3 -m build --sdist --wheel --outdir "$tmp/out" "$tmp/python" >&2
for f in "$tmp/out"/draco_insomnis-*; do
  cp "$f" "$out/"
  echo "$out/$(basename "$f")"
done
