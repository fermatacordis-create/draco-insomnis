#!/usr/bin/env bash
# The crate in real servers, from the packaged .crate as a user gets it:
#   rust/e2e/run.sh dist/draco-insomnis-X.crate
# axum (tower layer) and actix-web (middleware), real sockets, real HTTP.
set -euo pipefail
crate=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
cd "$(dirname "$0")"
rm -rf .draco && mkdir .draco
tar -xzf "$crate" -C .draco --strip-components=1
cargo run --quiet --release
