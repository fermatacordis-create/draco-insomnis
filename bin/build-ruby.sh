#!/usr/bin/env bash
# Builds the Ruby gem from ruby/ (no dependencies at run time). Uses the local "gem" when there is one,
# otherwise the official ruby image.
# Usage: bin/build-ruby.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r ruby "$tmp/ruby"
cp LICENSE "$tmp/ruby/LICENSE"
# The commit's time in the archive, so the same commit builds the same gem.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
if command -v gem >/dev/null 2>&1; then
  (cd "$tmp/ruby" && gem build --quiet draco-insomnis.gemspec >&2)
else
  docker run --rm -e SOURCE_DATE_EPOCH -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$tmp/ruby":/gem -w /gem ruby:3.4 gem build --quiet draco-insomnis.gemspec >&2
fi
gem=$(ls "$tmp/ruby"/draco-insomnis-*.gem)
cp "$gem" "$out/"
echo "$out/$(basename "$gem")"
