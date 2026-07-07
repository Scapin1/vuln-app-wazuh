# API Contract — Frontend → Backend

## Contexto

El frontend actual trae TODAS las vulnerabilidades a memoria (`PAGE_SIZE=10000`, while loop).
Con 20M+ registros el browser crashea. Necesitamos endpoints de agregación en backend.

---

### 1. Dashboard Summary

```
GET /api/vulns/dashboard?connection_id={id}&period={period}&date={YYYY-MM-DD}
```

| Param          | Type   | Default | Description                      |
| -------------- | ------ | ------- | -------------------------------- |
| `connection_id` | int    | —       | ID de conexión Wazuh (requerido) |
| `period`        | string | `30d`   | `24h`, `7d`, `30d`, `all`        |
| `date`          | string | —       | Si `period=day`, fecha `YYYY-MM-DD` |

**Response** (200):
```json
{
  "severity_distribution": { "CRITICAL": int, "HIGH": int, "MEDIUM": int, "LOW": int },
  "status_distribution":   { "Detected": int, "Resolved": int, "Re-emerged": int },
  "total": int
}
```

---

### 2. Timeline Gantt (CVE Snapshots — paginado)

```
GET /api/vulns/timeline/gantt?connection_id={id}&period={period}&page={n}&per_page={n}&agent={name}&severity={level}&search={text}
```

| Param          | Type   | Default | Description                                      |
| -------------- | ------ | ------- | ------------------------------------------------ |
| `connection_id` | int    | —       | ID de conexión (requerido)                       |
| `period`        | string | `all`   | `24h`, `7d`, `30d`, `all`                        |
| `date`          | string | —       | Si `period=day`, fecha `YYYY-MM-DD`              |
| `agent`         | string | —       | Filtrar por `agent_name`                        |
| `severity`      | string | —       | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`              |
| `search`        | string | —       | Búsqueda parcial en `cve_id` o `description`     |
| `page`          | int    | `1`     | Número de página                                 |
| `per_page`      | int    | `20`    | Items por página                                 |

**Response** (200):
```json
{
  "cves": [
    {
      "cve_id": string,
      "severity": string,
      "description": string,
      "snapshots": [
        {
          "sync_timestamp": string (ISO8601),
          "agent_count": int,
          "agents": string[] (opcional)
        }
      ],
      "first_sync": string (ISO8601) | null,
      "last_sync": string (ISO8601) | null,
      "is_resolved": bool
    }
  ],
  "total_cves": int,
  "total_pages": int,
  "current_page": int,
  "per_page": int,
  "min_timestamp": string (ISO8601),
  "max_timestamp": string (ISO8601)
}
```

**Notas**:
- `sync_timestamp`: momento de sincronización Wazuh donde se detectó la CVE
- `is_resolved`: el último snapshot de ese CVE tiene `agent_count === 0`
- `min_timestamp` / `max_timestamp`: rango global de TODOS los CVEs (no solo página actual). Es necesario para renderizar el header del timeline.
- `agents` puede omitirse si hay demasiados (>500). El frontend es robusto a eso.

---

### 3. Analytics Summary

```
GET /api/vulns/analytics?connection_id={id}&period={period}&date={YYYY-MM-DD}
```

| Param          | Type   | Default | Description                      |
| -------------- | ------ | ------- | -------------------------------- |
| `connection_id` | int    | —       | ID de conexión (requerido)       |
| `period`        | string | `30d`   | `24h`, `7d`, `30d`, `all`        |
| `date`          | string | —       | Si `period=day`, fecha           |

**Response** (200):
```json
{
  "severity_distribution": { "CRITICAL": int, "HIGH": int, "MEDIUM": int, "LOW": int },
  "status_distribution":   { "Activo": int, "Resuelto": int, "Reabierto": int },
  "top_agents":            [ { "agent": string, "count": int } ],
  "critical_count": int,
  "top_critical_cve": string | null
}
```

---

### 4. Filter Options

```
GET /api/vulns/filter-options?connection_id={id}
```

| Param          | Type | Default | Description                |
| -------------- | ---- | ------- | -------------------------- |
| `connection_id` | int  | —       | ID de conexión (requerido) |

**Response** (200) — versión con counts (preferida):
```json
{
  "agents": [ { "name": string, "count": int } ],
  "cves":   [ { "id": string, "count": int } ]
}
```
Alternativa solo nombres:
```json
{
  "agents": string[],
  "cves": string[]
}
```

---

### 5. Timeline Events

```
GET /api/vulns/events?connection_id={id}&start_ms={unix_ms}&end_ms={unix_ms}
```

| Param          | Type  | Default | Description                  |
| -------------- | ----- | ------- | ---------------------------- |
| `connection_id` | int   | —       | ID de conexión (requerido)   |
| `start_ms`      | int   | —       | Unix ms del inicio del rango |
| `end_ms`        | int   | —       | Unix ms del fin del rango    |

**Response** (200):
```json
{
  "detections":  [ { "cve_id": string, "timestamp": string (ISO8601), "agent": string } ],
  "resolutions": [ { "cve_id": string, "timestamp": string (ISO8601), "agent": string } ]
}
```

---

### Convenciones Generales

- **Base URL**: `/api/vulns`
- **Autenticación**: Misma que endpoints existentes (token JWT en header)
- **Errores**: Siempre `{ "error": string }` con HTTP code apropiado (400/404/500)
- **Timestamps**: Siempre ISO 8601 (`2026-03-01T00:00:00Z`) — NO unix timestamps
- **Conexión inválida**: 404
- **Soporte AbortController**: El frontend usa `AbortController` (signal de axios)

### Endpoints Legacy (solo fallback)

- `GET /api/vulns?connection_id=X&limit=10000&offset=0` — usado solo si los nuevos endpoints no responden
