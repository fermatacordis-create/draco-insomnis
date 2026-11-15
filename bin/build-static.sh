#!/usr/bin/env bash
# Builds the static-site generator as ONE self-contained HTML file (static/index.html with
# static/generator.mjs inlined): it works opened from the disk, from GitHub Pages or anywhere.
# Usage: bin/build-static.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
out="${1:-dist}"
mkdir -p "$out"
dest="$(cd "$out" && pwd)/draco-insomnis-static-$version.html"
node --input-type=module - "$dest" "$version" <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
const [dest, version] = process.argv.slice(2);
const page = readFileSync('static/index.html', 'utf8');
// The module's exports become the "G" object the page uses.
const mod = readFileSync('static/generator.mjs', 'utf8');
const names = [...mod.matchAll(/^export (?:const|function) (\w+)/gm)].map((m) => m[1]);
const inlined = mod.replace(/^export /gm, '') + `\nconst G = { ${names.join(', ')} };\n`;
const marker = "import * as G from './generator.mjs';";
if (!page.includes(marker)) throw new Error('marker not found in static/index.html');
const html = page.replace(marker, () => inlined).replace('</footer>', ` Version ${version}.</footer>`);
writeFileSync(dest, html);
JS
echo "$dest"
