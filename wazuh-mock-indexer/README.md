# Wazuh Mock Indexer

Simula un Wazuh Indexer (OpenSearch) para pruebas de carga y validación del pipeline de sync de `vuln-app-wazuh`.

## Qué hace

Reemplaza al Wazuh Indexer real con un server HTTP que:

- Expone exactamente el mismo endpoint `POST /wazuh-states-vulnerabilities-*/_search` que OpenSearch
- Usa Basic Auth (acepta cualquier usuario/contraseña)
- Soporta paginación con `search_after`
- Genera datos deterministas con seed (mismo seed → mismos datos siempre)

La app **no sabe** que no es real — se conecta, sincroniza, y funciona exactamente igual.

## Requisitos

- Python 3.10+
- `pip install -r requirements.txt`

## Uso rápido

```bash
# 1. Parar el mock
cd wazuh-mock-indexer
pip install -r requirements.txt
python server.py
```

Esto levanta el mock en `http://0.0.0.0:9200` con 500 agents y 4M detecciones.

```bash
# 2. En la app, crear una conexión Wazuh apuntando al mock
#    URL: http://<host-docker-o-ip>:9200
#    User: cualquier cosa (mock acepta todas)
#    Password: cualquier cosa

# 3. Disparar sync desde la UI o vía API
#    POST /wazuh-connections/{id}/sync
```

## Parámetros

| Parámetro       | Default               | Descripción                              |
| --------------- | --------------------- | ---------------------------------------- |
| `--agents`      | 500                   | Cantidad de agentes simulados            |
| `--detections`  | 4,000,000             | Cantidad de detecciones de vulnerabilidad |
| `--cves`        | 20,000                | Catálogo de CVEs únicos                  |
| `--seed`        | 42                    | Seed para datos deterministas            |
| `--start`       | 2026-04-01T00:00:00Z  | Inicio de la ventana temporal            |
| `--end`         | 2026-07-01T00:00:00Z  | Fin de la ventana temporal               |
| `--port`        | 9200                  | Puerto del servidor mock                 |
| `--host`        | 0.0.0.0               | Interfaz de red                          |

Ejemplos:

```bash
# Prueba chica (rápida)
python server.py --agents 50 --detections 50000 --port 9201

# Prueba gigante (estrés)
python server.py --agents 1000 --detections 10000000 --port 9200
```

## Con Docker

Si la app corre en Docker, el mock necesita estar en la misma network:

```bash
# Opción A: correr el mock en el host y conectar usando host.docker.internal
python server.py --host 0.0.0.0 --port 9200

# Opción B: agregar el mock al docker-compose.yml como servicio
```

Para Opción B, agregá esto a `docker-compose.yml`:

```yaml
  wazuh-mock:
    build: ./wazuh-mock-indexer
    container_name: wazuh-mock
    ports:
      - "9200:9200"
    networks:
      - app-network
    command: python server.py --agents 500 --detections 4000000
```

Y un Dockerfile mínimo (`wazuh-mock-indexer/Dockerfile`):

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 9200
CMD ["python", "server.py"]
```

## Arquitectura

```
┌─────────────────────────────┐
│   Wazuh Mock Indexer        │
│   localhost:9200             │
│                             │
│   GET  /                    │ → 200 OK (health check)
│   POST /{index}/_search     │ → resultados paginados (formato OpenSearch)
│   GET  /_cat/indices        │ → info del índice
└──────────┬──────────────────┘
           │
           │ httpx (Basic Auth, search_after pagination)
           ▼
┌─────────────────────────────┐
│   vuln-api (FastAPI)        │
│   POST /{conn_id}/sync      │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│   TimescaleDB               │
└─────────────────────────────┘
```

## Cómo mide la performance

1. Anotá la hora antes de iniciar el sync
2. Iniciá el sync desde la UI o API
3. Revisá los logs de `vuln-api` — cada batch procesado muestra `Sincronizadas: 5000`
4. Al final muestra el total sincronizado y el tiempo

Para métricas más finas, podés revisar:

- **Logs de la API**: `docker logs api -f` mientras sincroniza
- **Logs del mock**: la consola donde corre `server.py`
- **SonarCloud**: cobertura de código nueva (si probás después de cambios)
