#!/usr/bin/env bash
# Builds the Rust crate from rust/: draco-insomnis-X.crate, the same file crates.io would get
# (cargo package checks that it builds). Uses the local "cargo" when there is one, otherwise the
# official Rust image.
# Usage: bin/build-rust.sh [output-dir]   (default: ./dist); prints the path of the crate.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/rust"
cp -r rust/src rust/Cargo.toml rust/Cargo.lock rust/README.md "$tmp/rust/"
cp LICENSE "$tmp/rust/LICENSE"
args=(package --locked --allow-dirty --quiet --target-dir "$tmp/target")
if command -v cargo >/dev/null 2>&1; then
  (cd "$tmp/rust" && cargo "${args[@]}" >&2)
else
  args[5]=/w/target
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -v "$tmp":/w -w /w/rust rust:1 cargo "${args[@]}" >&2
fi
crate=$(ls "$tmp"/target/package/draco-insomnis-*.crate)
cp "$crate" "$out/"
echo "$out/$(basename "$crate")"
