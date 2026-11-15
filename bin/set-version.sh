#!/usr/bin/env bash
# Sets the same version on every package: the WordPress plugin (header, constant, Stable tag) and the
# PrestaShop, Drupal, Joomla and Moodle packages, the server edition and the JavaScript package.
# Moodle's own build number (YYYYMMDDXX) goes up too.
# Usage: bin/set-version.sh X.Y.Z     (then add a changelog entry in readme.txt)
set -euo pipefail
cd "$(dirname "$0")/.."
v="${1:-}"
[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Usage: bin/set-version.sh X.Y.Z" >&2; exit 1; }

sed -i "s/^\( \* Version: *\)[0-9.]*$/\1$v/" draco-insomnis.php
sed -i "s/^define('DRACO_INSOMNIS_VERSION', '[^']*');/define('DRACO_INSOMNIS_VERSION', '$v');/" draco-insomnis.php
sed -i "s/^Stable tag: .*/Stable tag: $v/" readme.txt
sed -i "s/\(\$this->version = '\)[^']*'/\1$v'/" cms/prestashop/dracoinsomnis/dracoinsomnis.php
sed -i "s/^version: '[^']*'/version: '$v'/" cms/drupal/draco_insomnis/draco_insomnis.info.yml
sed -i "s/<version>[^<]*<\/version>/<version>$v<\/version>/" cms/joomla/plg_system_dracoinsomnis/dracoinsomnis.xml

sed -i "s/^define('DRACO_SERVER_VERSION', '[^']*');/define('DRACO_SERVER_VERSION', '$v');/" server/bin/draco
sed -i "s/^define('DRACO_SERVER_GUARD', '[^']*');/define('DRACO_SERVER_GUARD', '$v');/" server/guard.php

sed -i "0,/\"version\": \"[^\"]*\"/s//\"version\": \"$v\"/" js/package.json
sed -i "0,/^  \"version\": /s/^  \"version\": \"[^\"]*\"/  \"version\": \"$v\"/; 0,/^      \"version\": /s/^      \"version\": \"[^\"]*\"/      \"version\": \"$v\"/" js/package-lock.json
sed -i "s/^export const VERSION = '[^']*';/export const VERSION = '$v';/" js/src/index.ts
sed -i "0,/^version = \"[^\"]*\"/s//version = \"$v\"/" python/pyproject.toml
sed -i "s#\(github.com/fermatacordis-create/draco-insomnis/go/draco v\)[0-9.]*#\1$v#" go/caddy/go.mod
sed -i "s/^const Version = \"[^\"]*\"/const Version = \"$v\"/" go/draco/gatekeeper.go
sed -i "s/^  VERSION = '[^']*'/  VERSION = '$v'/" ruby/lib/draco_insomnis/version.rb
sed -i "s#<Version>[^<]*</Version>#<Version>$v</Version>#" dotnet/DracoInsomnis/DracoInsomnis.csproj
sed -i "s/public const string Version = \"[^\"]*\";/public const string Version = \"$v\";/" dotnet/DracoInsomnis/Gatekeeper.cs
sed -i "s/^__version__ = \"[^\"]*\"/__version__ = \"$v\"/" python/src/draco_insomnis/__init__.py
# JVM: the first <version> of each pom is the project's own; the e2e apps ask for the same version.
sed -i "0,/^  <version>[^<]*<\/version>/s//  <version>$v<\/version>/" java/pom.xml java/draco/pom.xml java/ktor/pom.xml
sed -i "s#<draco.version>[^<]*</draco.version>#<draco.version>$v</draco.version>#" java/e2e/spring/pom.xml java/e2e/ktor/pom.xml
sed -i "s/public static final String VERSION = \"[^\"]*\";/public static final String VERSION = \"$v\";/" java/draco/src/main/java/dracoinsomnis/Gatekeeper.java
# Rust: the crate, its own entry in Cargo.lock and the constant.
sed -i "0,/^version = \"[^\"]*\"/s//version = \"$v\"/" rust/Cargo.toml
sed -i "/^name = \"draco-insomnis\"$/{n;s/^version = \"[^\"]*\"/version = \"$v\"/}" rust/Cargo.lock
sed -i "s/^pub const VERSION: &str = \"[^\"]*\";/pub const VERSION: \&str = \"$v\";/" rust/src/gatekeeper.rs

moodle=cms/moodle/local_dracoinsomnis/version.php
sed -i "s/^\(\$plugin->release = '\)[^']*'/\1$v'/" "$moodle"
current=$(sed -n 's/^\$plugin->version = \([0-9]*\);.*/\1/p' "$moodle")
build=$(( $(date -u +%Y%m%d) * 100 ))
[ "$build" -gt "$current" ] || build=$(( current + 1 ))
sed -i "s/^\(\$plugin->version = \)[0-9]*;/\1$build;/" "$moodle"

bin/versions.sh --check "$v"
grep -q "^= $v =" readme.txt || echo "Remember: add a '= $v =' entry to the changelog in readme.txt" >&2
