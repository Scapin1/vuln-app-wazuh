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

### 2. Timeline Gantt (CVE Snapshots — paginado)

```
GET /api/vulns/timeline/gantt?connection_id={id}&period={period}&page={n}&per_page={n}&agent={name}&severity={level}&search={text}
```

**Purpose**: Reemplaza `GanttTab.vue buildCveSnapshots()`. El backend agrupa por `cve_id`,
colecta los `sync_timestamp` (momentos de sincronización Wazuh), y arma snapshots
con los agentes afectados en cada timestamp. El frontend evita traer TODAS las vulns.

| Param          | Type   | Default | Description                                      |
| -------------- | ------ | ------- | ------------------------------------------------ |
| `connection_id` | int    | —       | ID de conexión (requerido)                       |
| `period`        | string | `all`   | `24h`, `7d`, `30d`, `all`. Filtra CVEs activos en el período |
| `date`          | string | —       | Si `period=day`, fecha `YYYY-MM-DD`              |
| `agent`         | string | —       | Filtrar por agent_name                           |
| `severity`      | string | —       | Filtrar por severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `search`        | string | —       | Búsqueda parcial en `cve_id` o `description`     |
| `page`          | int    | `1`     | Número de página                                 |
| `per_page`      | int    | `20`    | Items por página. El frontend usa 20.            |

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
      "first_sync": "2026-03-01T00:00:00Z",
      "last_sync": "2026-04-01T00:00:00Z",
      "is_resolved": false
    }
  ],
  "total_cves": 10234,
  "total_pages": 512,
  "current_page": 1,
  "per_page": 20,
  "min_timestamp": "2024-01-15T00:00:00Z",
  "max_timestamp": "2026-07-07T00:00:00Z"
}
```

**Campos críticos:**

- **`sync_timestamp`** (dentro de cada snapshot): momentos de sincronización Wazuh donde se detectó
  vulnerabilidad. ISO8601 string. El frontend usa `new Date()` directo.
- **`agents`**: lista de agent_name afectados en ese timestamp. Si hay 500+ agentes por CVE,
  puede omitirse y mandar solo `agent_count` (el tooltip mostrará "N agentes afectados" sin nombres).
  El frontend es robusto a `agents: undefined` o `agents: []`.
- **`is_resolved`**: `true` SOLO cuando el ULTIMO snapshot de ese CVE tiene `agent_count: 0`
  (todos los agentes resolvieron la vulnerabilidad). NO se define por un campo en la tabla de vulns,
  sino por la ausencia de agentes en el último snapshot.
- **`first_sync`** / **`last_sync`**: primer y último timestamp del array de snapshots.
  Usados para calcular duración de la barra.
- **`min_timestamp` / `max_timestamp`** (metadata global): El rango de tiempo total considerando
  TODOS los CVEs del conjunto filtrado (no solo de esta página). El frontend NECESITA esto para
  dibujar el header del timeline (etiquetas de meses/años). Sin esto, solo vería el rango de la
  página actual, que es muy angosto.

**Cómo se construyen los snapshots (backend):**

```
Por cada vuln record único (cve_id + agent_name + sync_timestamp):
  1. Agrupar todos los registros por cve_id
  2. Para cada CVE, colectar todos los (sync_timestamp, agent_name) únicos
  3. Ordenar timestamps ascendente
  4. Cada timestamp único → un snapshot con:
     - sync_timestamp
     - agent_count = cantidad de agentes únicos en ese timestamp
     - agents = lista de agentes (opcional, solo si < umbral)
  5. is_resolved = el último snapshot tiene agent_count === 0
  6. Calcular min/max global sobre TODOS los CVEs (no solo esta página)
```

**Snapshot merging**: El frontend MERGEA snapshots cercanos según el nivel de zoom (año/mes/día/hora).
El backend debe devolver TODOS los snapshots, SIN mergear. El merge depende del zoom actual que
cambia dinámicamente.

**Performance**: Si hay CVEs con 10.000+ snapshots (vuln que se detecta/resuelve/reabre constantemente
con cada sync), considerar limitar a los últimos 1000 snapshots por CVE o muestrear. El frontend
mergea por zoom así que no pierde precisión visible.

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
