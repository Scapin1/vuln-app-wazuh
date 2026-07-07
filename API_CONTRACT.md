# API Contract — Frontend → Backend

## Contexto

El frontend actual trae TODAS las vulnerabilidades a memoria (`PAGE_SIZE=10000`, while loop).
Con 20M+ registros el browser crashea. Necesitamos endpoints de agregación en backend.

## Endpoints Requeridos

---

### 1. Dashboard Summary

```
GET /api/vulns/dashboard?connection_id={id}&period={period}
```

**Purpose**: Reemplaza `Dashboard.vue buildDashboard()` — traer todas las vulns para calcular charts.
Ahora el backend calcula las distribuciones directamente en DB.

| Param          | Type   | Default | Description                      |
| -------------- | ------ | ------- | -------------------------------- |
| `connection_id` | int    | —       | ID de conexión Wazuh (requerido) |
| `period`        | string | `30d`   | `24h`, `7d`, `30d`, `all`        |
| `date`          | string | —       | Si `period=day`, fecha `YYYY-MM-DD` |

**Response** (200):
```json
{
  "severity_distribution": {
    "CRITICAL": 120,
    "HIGH": 340,
    "MEDIUM": 560,
    "LOW": 180
  },
  "status_distribution": {
    "Detected": 800,
    "Resolved": 200,
    "Re-emerged": 100
  },
  "total": 1100
}
```

**Error** (400/500):
```json
{
  "error": "Conexión no encontrada"
}
```

---

### 2. Timeline / Gantt Data (paginado)

```
GET /api/vulns/timeline?connection_id={id}&period={period}&page={n}&per_page={n}
```

**Purpose**: Reemplaza `GanttTab.vue buildCveSnapshots()` — el backend agrupa por CVE y construye snapshots.
Acepta los mismos filtros que dashboard + paginación.

| Param          | Type   | Default | Description                      |
| -------------- | ------ | ------- | -------------------------------- |
| `connection_id` | int    | —       | ID de conexión (requerido)       |
| `period`        | string | `30d`   | `24h`, `7d`, `30d`, `all`        |
| `date`          | string | —       | Si `period=day`, fecha `YYYY-MM-DD` |
| `page`          | int    | `1`     | Número de página                 |
| `per_page`      | int    | `50`    | Items por página (max 100)       |

**Response** (200):
```json
{
  "cves": [
    {
      "cve_id": "CVE-2026-0001",
      "severity": "CRITICAL",
      "description": "RCE en modulo de autenticacion",
      "snapshots": [
        {
          "sync_timestamp": "2026-03-01T00:00:00Z",
          "agent_count": 3,
          "agents": ["srv-web-01", "srv-db-02", "srv-api-03"]
        },
        {
          "sync_timestamp": "2026-04-01T00:00:00Z",
          "agent_count": 2,
          "agents": ["srv-web-01", "srv-db-02"]
        }
      ],
      "first_seen": "2026-03-01T00:00:00Z",
      "last_seen": "2026-04-01T00:00:00Z",
      "is_resolved": false
    }
  ],
  "total_cves": 10234,
  "total_pages": 205,
  "current_page": 1,
  "per_page": 50
}
```

**Importante**: Los `sync_timestamp` deben ser strings ISO8601, NO timestamps numéricos.
El frontend usa `new Date()` directo.

**Paginación**: El frontend usa `total_pages` para mostrar controles. Si `total_pages=1`,
oculta la paginación.

---

### 3. Analytics Summary

```
GET /api/vulns/analytics?connection_id={id}&period={period}
```

**Purpose**: Reemplaza `VulnAnalytics.vue buildAnalytics()` — métricas específicas para la vista de analíticas.

| Param          | Type   | Default | Description                      |
| -------------- | ------ | ------- | -------------------------------- |
| `connection_id` | int    | —       | ID de conexión (requerido)       |
| `period`        | string | `30d`   | `24h`, `7d`, `30d`, `all`        |
| `date`          | string | —       | Si `period=day`, fecha           |

**Response** (200):
```json
{
  "severity_distribution": {
    "CRITICAL": 120,
    "HIGH": 340,
    "MEDIUM": 560,
    "LOW": 180
  },
  "status_distribution": {
    "Activo": 800,
    "Resuelto": 200,
    "Reabierto": 100
  },
  "top_agents": [
    { "agent": "srv-web-01", "count": 850 },
    { "agent": "srv-db-02", "count": 520 },
    { "agent": "srv-api-03", "count": 340 },
    { "agent": "srv-proxy-05", "count": 210 },
    { "agent": "srv-dhcp-01", "count": 95 }
  ],
  "critical_count": 120,
  "top_critical_cve": "CVE-2026-0001"
}
```

---

### 4. Filter Options

```
GET /api/vulns/filter-options?connection_id={id}
```

**Purpose**: Reemplaza el scraping de agentes/CVEs desde todos los datos en cliente.
Devuelve valores distintos para los dropdowns de filtros.

| Param          | Type | Default | Description                |
| -------------- | ---- | ------- | -------------------------- |
| `connection_id` | int  | —       | ID de conexión (requerido) |

**Response** (200):
```json
{
  "agents": [
    { "name": "srv-web-01", "count": 850 },
    { "name": "srv-db-02", "count": 520 }
  ],
  "cves": [
    { "id": "CVE-2026-0001", "count": 150 },
    { "id": "CVE-2026-0002", "count": 87 }
  ]
}
```

El `count` es opcional pero útil para ordenar. Si no lo tienen, solo el array de strings funciona:
```json
{
  "agents": ["srv-web-01", "srv-db-02"],
  "cves": ["CVE-2026-0001", "CVE-2026-0002"]
}
```

---

### 5. Timeline Events (para slots de línea de tiempo)

```
GET /api/vulns/events?connection_id={id}&start_ms={unix_ms}&end_ms={unix_ms}
```

**Purpose**: Reemplaza `useTimelineData.js buildChangeEvents()` — eventos de detección/resolución
dentro de un rango de tiempo para pintar los slots.

| Param          | Type  | Default | Description                  |
| -------------- | ----- | ------- | ---------------------------- |
| `connection_id` | int   | —       | ID de conexión (requerido)   |
| `start_ms`      | int   | —       | Unix ms del inicio del rango |
| `end_ms`        | int   | —       | Unix ms del fin del rango    |

**Response** (200):
```json
{
  "detections": [
    { "cve_id": "CVE-2026-0001", "timestamp": "2026-03-15T10:30:00Z", "agent": "srv-web-01" }
  ],
  "resolutions": [
    { "cve_id": "CVE-2026-0004", "timestamp": "2026-04-10T08:00:00Z", "agent": "srv-proxy-05" }
  ]
}
```

---

### Convenciones Generales

- **Base URL**: `/api/vulns` (ya existe, pero se agregan rutas)
- **Autenticación**: Misma que los endpoints existentes (token JWT en header)
- **Errores**: Siempre devolver `{ "error": "mensaje" }` con código HTTP apropiado
- **Timestamps**: Siempre ISO 8601 (`2026-03-01T00:00:00Z`) — NO unix timestamps
- **Conexión inválida**: Si `connection_id` no existe, devolver 404
- **Timeout**: El frontend tiene `AbortController`, pueden cancelar requests. Soporten `signal` de axios

### Endpoints que se dejan de usar (frontend legacy)

Estos endpoints quedan para consultas raw, pero las vistas principales NO los van a consumir más:

- `GET /api/vulns?connection_id=X&limit=10000&offset=0` — usado por Dashboard / Timeline / VulnAnalytics
- Ahora el frontend solo lo usará si los nuevos endpoints no están disponibles (fallback)
