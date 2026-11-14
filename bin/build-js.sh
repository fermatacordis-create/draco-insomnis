#!/usr/bin/env bash
# Builds the JavaScript package (js/: Node.js, Express, Koa, Strapi, Directus, Cloudflare Workers) as an
# npm tarball, after its tests pass. Install it with: npm install ./draco-insomnis-js-X.Y.Z.tgz
# Usage: bin/build-js.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd js
[ "$(node -p 'require("./package.json").version')" = "$version" ] || { echo "js/package.json is not at $version (run bin/set-version.sh $version)" >&2; exit 1; }
npm ci --no-audit --no-fund >&2
npm run typecheck >&2
npm test >&2
cp ../LICENSE LICENSE
trap 'rm -f LICENSE' EXIT
name=$(npm pack --silent --pack-destination "$out")
mv "$out/$name" "$out/draco-insomnis-js-$version.tgz"
echo "$out/draco-insomnis-js-$version.tgz"
