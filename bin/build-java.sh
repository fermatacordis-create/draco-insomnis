#!/usr/bin/env bash
# Builds the JVM jars from java/: draco-insomnis-X.jar (the engine and the Servlet filter, no
# dependencies) and draco-insomnis-ktor-X.jar (the Ktor plugin). Reproducible: the same sources give
# the same bytes. Uses the local "mvn" when there is one, otherwise the official Maven image.
# Usage: bin/build-java.sh [output-dir]   (default: ./dist); prints the path of each jar.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/java" "$tmp/m2"
cp -r java/pom.xml java/draco java/ktor "$tmp/java/"
rm -rf "$tmp/java/draco/target" "$tmp/java/ktor/target"
args=(-B -ntp -q -DskipTests "-Dmaven.repo.local=$tmp/m2" package)
if command -v mvn >/dev/null 2>&1; then
  (cd "$tmp/java" && mvn "${args[@]}" >&2)
else
  args[4]="-Dmaven.repo.local=/w/m2"
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e MAVEN_CONFIG=/tmp/.m2 -v "$tmp":/w -w /w/java \
    maven:3.9-eclipse-temurin-21 mvn "${args[@]}" >&2
fi
version=$(sed -n 's:^  <version>\(.*\)</version>:\1:p' java/draco/pom.xml | head -1)
for jar in "draco/target/draco-insomnis-$version.jar" "ktor/target/draco-insomnis-ktor-$version.jar"; do
  cp "$tmp/java/$jar" "$out/"
  echo "$out/$(basename "$jar")"
done
