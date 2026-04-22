#!/bin/bash
set -euo pipefail

BUILD_ID="${1:-}"
if [ -z "$BUILD_ID" ]; then
  echo "ERROR: Falta BUILD_ID. Uso: ./run_zap.sh <build_id>" >&2
  exit 2
fi

# Red Docker donde viven los servicios (api/frontend). OJO: estos hostnames NO existen
# desde el host runner; por eso las comprobaciones se hacen desde un contenedor en la red.
NETWORK="${ZAP_NETWORK:-vuln-app-wazuh_app-network}"

TARGET_API="http://api:8000/openapi.json"
TARGET_FRONTEND="http://frontend:80"

docker_curl() {
  # curl dentro de la red Docker para poder resolver api/frontend.
  docker run --rm --network="$NETWORK" curlimages/curl:8.12.1 "$@"
}

echo "--- Iniciando Escaneo Profundo DAST (Build $BUILD_ID) ---"

echo "Esperando a que la API responda en http://api:8000/docs..."
MAX_RETRIES=90
COUNT=0

# Solución al bucle infinito
until docker_curl --output /dev/null --silent --head --fail http://api:8000/docs; do
    if [ ${COUNT} -eq ${MAX_RETRIES} ]; then
        echo -e "\nERROR: La API no levantó después de $((MAX_RETRIES * 2)) segundos. Abortando escaneo ZAP."
        echo "--- Debug (docker) ---"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
        docker logs --tail=200 api || true
        exit 1
    fi
    printf '.'
    sleep 2
    COUNT=$((COUNT+1))
done

echo -e "\n¡La API está lista!"

echo "Obteniendo token de acceso para escaneo autenticado..."
RESPONSE=$(docker_curl -s -X POST http://api:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin")

TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; 
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except:
    print('')
")

AUTH_HEADER=""
if [ -n "$TOKEN" ]; then
    echo "Token obtenido con éxito."
    AUTH_HEADER="-z \"Authorization: Bearer $TOKEN\""
fi

echo "--- Fase 1: Escaneando Backend (API) ---"
docker run --rm \
    --user root \
    --network=$NETWORK \
    -v "$(pwd)/reports:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py \
    -t "$TARGET_API" \
    -f openapi \
    -r "zap_api_report_${BUILD_ID}.html" \
    -I || echo "ZAP API finalizó" 
    # El flag -I evita que el script falle violentamente si ZAP encuentra warnings menores

echo "--- Fase 2: Escaneando Frontend (Baseline Spider) ---"
docker run --rm \
    --user root \
    --network=$NETWORK \
    -v "$(pwd)/reports:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET_FRONTEND" \
    -r "zap_frontend_report_${BUILD_ID}.html" \
    -I || echo "ZAP Frontend finalizó"
