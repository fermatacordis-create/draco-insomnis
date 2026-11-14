#!/usr/bin/env bash
# Builds the Draco Insomnis add-on image for PHP containers (server/docker/Dockerfile).
# Usage: bin/build-docker.sh [tag ...]   (default tag: draco-insomnis:<version>)
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(sed -n "s/^define('DRACO_SERVER_VERSION', '\([^']*\)');/\1/p" server/bin/draco)
ctx=server/docker/build/draco
rm -rf server/docker/build && mkdir -p "$ctx/share/bin" "$ctx/share/src" "$ctx/share/core"
cp server/guard.php server/autoload.php "$ctx/share/"
cp server/src/*.php "$ctx/share/src/"
cp src/Core/*.php "$ctx/share/core/"
cp server/bin/draco "$ctx/share/bin/draco"
cp LICENSE "$ctx/share/LICENSE"
cp server/etc/draco.ini "$ctx/draco.ini"
cp server/docker/install-docker.sh server/docker/fill-volume.sh "$ctx/"
echo "$v" > "$ctx/VERSION"
tags=("$@"); [ ${#tags[@]} -gt 0 ] || tags=("draco-insomnis:$v")
args=(); for t in "${tags[@]}"; do args+=(-t "$t"); done
docker build --build-arg "DRACO_VERSION=$v" -f server/docker/Dockerfile "${args[@]}" . >&2
rm -rf server/docker/build
printf '%s\n' "${tags[@]}"
