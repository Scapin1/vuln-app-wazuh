#!/bin/bash
TARGET=$1      # http://api:8000/openapi.json
BUILD_ID=$2
NETWORK="vuln-app-wazuh_app-network"

echo "--- Iniciando Escaneo Profundo (Build $BUILD_ID) ---"

until $(curl --output /dev/null --silent --head --fail http://api:8000/docs); do
    printf '.'
    sleep 2
done

echo "Intentando registrar usuario admin (por si la DB está vacía)..."
# 2. Obtener Token
echo "Obteniendo token de acceso..."
RESPONSE=$(curl -s -X POST http://api:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin")

TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; 
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except:
    print('')
")

if [ -z "$TOKEN" ]; then
    echo "ADVERTENCIA: No se pudo obtener token. El escaneo será limitado (solo endpoints públicos)."
    AUTH_HEADER=""
else
    echo "Token obtenido con éxito. ZAP escaneará como usuario autenticado."
    # Pasamos el token como un header adicional a zap-api-scan
    AUTH_HEADER="-z \"Authorization: Bearer $TOKEN\""
fi
docker run --rm \
    --user root \
    --network=$NETWORK \
    -v "$(pwd)/reports:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t "$TARGET" -f openapi \
    -r "zap_report.html" \
    -J "zap_report.json" \
    -z "Authorization: Bearer $TOKEN" || echo "ZAP finalizó"
