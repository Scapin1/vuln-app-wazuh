#!/bin/bash

TARGET_URL=$1
SCAN_ID=$2

echo "Ejecutando OWASP ZAP contra: $TARGET_URL"

docker run --rm \
  --network host \
  -v $(pwd):/zap/wrk:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t "$TARGET_URL" \
  -r "zap_report_${SCAN_ID}.html" \
  -J "zap_report_${SCAN_ID}.json" \
  -I

echo "Reporte generado: zap_report_${SCAN_ID}.html"