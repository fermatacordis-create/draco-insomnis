#!/usr/bin/env bash
# Builds the NuGet package from dotnet/DracoInsomnis (no dependencies beyond ASP.NET Core). Uses the
# local "dotnet" when there is one, otherwise the official SDK image.
# Usage: bin/build-dotnet.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/dotnet" "$tmp/pkg"
cp -r dotnet/DracoInsomnis dotnet/README.md "$tmp/dotnet/"
rm -rf "$tmp/dotnet/DracoInsomnis/bin" "$tmp/dotnet/DracoInsomnis/obj"
# Deterministic compiler output, with paths that do not depend on this machine.
args=(pack DracoInsomnis -c Release --nologo -v q -p:ContinuousIntegrationBuild=true)
if command -v dotnet >/dev/null 2>&1; then
  (cd "$tmp/dotnet" && dotnet "${args[@]}" -o "$tmp/pkg" >&2)
else
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e DOTNET_CLI_HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    -e DOTNET_NOLOGO=1 -v "$tmp":/w -w /w/dotnet mcr.microsoft.com/dotnet/sdk:9.0 dotnet "${args[@]}" -o /w/pkg >&2
fi
pkg=$(ls "$tmp/pkg"/DracoInsomnis.*.nupkg)
cp "$pkg" "$out/"
echo "$out/$(basename "$pkg")"
