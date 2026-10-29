#!/usr/bin/env bash
set -e

if ! command -v javac >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openjdk-17-jdk-headless
fi

npx vite build
javac backend/CyberShieldServer.java
exec java -cp backend CyberShieldServer
