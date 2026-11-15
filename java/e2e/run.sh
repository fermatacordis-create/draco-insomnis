#!/usr/bin/env bash
# The jars in real apps, installed as a user installs them from the release:
#   java/e2e/run.sh dist/draco-insomnis-X.jar dist/draco-insomnis-ktor-X.jar
# Spring Boot (Spring MVC on Tomcat) and Ktor (Netty). Needs Maven and a JDK 17 or newer.
set -euo pipefail
core=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
ktor=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
cd "$(dirname "$0")"
version=$(basename "$core" .jar)
version=${version#draco-insomnis-}
# The pom inside each jar is complete, so install-file needs nothing else.
mvn -B -ntp -q org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file -Dfile="$core"
mvn -B -ntp -q org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file -Dfile="$ktor"
(cd spring && mvn -B -ntp -q -Ddraco.version="$version" compile exec:java)
(cd ktor && mvn -B -ntp -q -Ddraco.version="$version" compile exec:java)
