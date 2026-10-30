#!/usr/bin/env bash
set -e

if ! command -v javac >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openjdk-17-jdk-headless
fi

mkdir -p backend/out
javac -d backend/out backend/ScanResultModel.java backend/ScanHistoryJavaStore.java backend/GeminiJavaService.java backend/CyberShieldWebUi.java backend/CyberShieldServer.java backend/CyberShieldServerTest.java
exec java -cp backend/out CyberShieldServer
