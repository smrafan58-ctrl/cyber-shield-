#!/usr/bin/env bash
set -e

if ! command -v javac >/dev/null 2>&1; then
  if [ "$(id -u)" = "0" ]; then
    (DEBIAN_FRONTEND=noninteractive apt-get update && \
     DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openjdk-17-jdk-headless) || true
  fi
fi

if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
  mkdir -p backend/out
  javac -d backend/out backend/ScanResultModel.java backend/ScanHistoryJavaStore.java backend/GeminiJavaService.java backend/CyberShieldWebUi.java backend/CyberShieldServer.java backend/CyberShieldServerTest.java
  exec java -cp backend/out CyberShieldServer
else
  echo "[CyberShield] Java runtime not present in container. Starting Node/TypeScript server..."
  exec node server.ts
fi
