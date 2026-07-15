<template>
  <div class="card gantt-card">
    <div v-if="ganttData === null" class="gantt-loading-state">
      <div class="gantt-spinner"></div>
      <p>Cargando datos de vulnerabilidades...</p>
    </div>

    <div v-else-if="!cveSnapshots.length" class="gantt-empty-state">
      <p>No hay datos de vulnerabilidades para mostrar</p>
    </div>

    <template v-else>
      <div class="gantt-header">
        <h3 class="gantt-title">Seguimiento de CVEs</h3>
        <div class="gantt-controls">
          <div class="search-date">
            <label for="ganttSearchDate" class="search-date-label">Buscar fecha:</label>
            <button class="date-trigger" @click="toggleDatePicker">
              <span>{{ formattedSearchDate || 'Seleccionar...' }}</span>
              <span class="cal-icon">📅</span>
            </button>
            <div v-if="showDatePicker" class="date-popup" ref="datePopupRef">
              <div class="popup-row">
                <select v-model="pickerYear" class="popup-sel" @click.stop>
                  <option v-for="y in years" :key="y" :value="y">{{ y }}</option>
                </select>
                <select v-model="pickerMonth" class="popup-sel" @click.stop>
                  <option v-for="(m, i) in MONTHS" :key="i" :value="i">{{ m }}</option>
                </select>
                <select v-model="pickerDay" class="popup-sel" @click.stop>
                  <option v-for="d in daysInMonth" :key="d" :value="d">{{ String(d).padStart(2, '0') }}</option>
                </select>
              </div>
              <div class="popup-row">
                <select v-model="pickerHour" class="popup-sel time-sel" @click.stop>
                  <option v-for="h in 24" :key="h-1" :value="String(h-1).padStart(2, '0')">{{ String(h-1).padStart(2, '0') }}</option>
                </select>
                <span class="time-sep">:</span>
                <select v-model="pickerMinute" class="popup-sel time-sel" @click.stop>
                  <option v-for="m in 60" :key="m-1" :value="String(m-1).padStart(2, '0')">{{ String(m-1).padStart(2, '0') }}</option>
                </select>
              </div>
              <div class="popup-actions">
                <button class="popup-btn cancel" @click="showDatePicker = false">Cancelar</button>
                <button class="popup-btn apply" @click="applyPickerDate">Aplicar</button>
              </div>
            </div>
            <button class="search-btn" @click="scrollToDate">Ir</button>
          </div>
          <div class="zoom-controls">
            <button class="zoom-btn" @click="zoomOut" title="Alejar">-</button>
            <span class="zoom-level">{{ zoomLabel }}</span>
            <button class="zoom-btn" @click="zoomIn" title="Acercar">+</button>
          </div>
          <div class="gantt-legend">
            <div class="legend-item"><span class="legend-dot snap-detected"></span> Activo</div>
            <div class="legend-item"><span class="legend-dot snap-reopened"></span> Reabierto</div>
            <div class="legend-item"><span class="legend-dot snap-resolved"></span> Resuelto</div>
          </div>
        </div>
      </div>

      <div class="gantt-scroll-wrapper" ref="scrollWrapper">
        <div class="gantt-header-row">
          <div class="gantt-sidebar-header">CVE / DETALLE</div>
          <div class="gantt-timeline-header" :style="{ minWidth: timelineWidth + 'px' }">
            <div v-for="label in timeLabels" :key="label.label" class="month-label"
              :style="{ width: MONTH_WIDTH + 'px' }">
              {{ label.label }}
            </div>
          </div>
        </div>

        <div class="gantt-body">
          <div v-for="cve in paginatedCveSnapshots" :key="cve.cve_id" class="gantt-row cve-row">
            <div class="gantt-sidebar-cell">
              <div class="cve-top">
                <span class="cve-id">{{ cve.cve_id }}</span>
                <span class="sev-badge" :class="cve.severity.toLowerCase()">{{ cve.severity }}</span>
              </div>
              <span class="cve-desc">{{ cve.description }}</span>
              <span class="cve-sync-count">{{ cve.snapshots.length }} sincronizaciones</span>
            </div>
            <div class="gantt-chart-cell" :style="{ minWidth: timelineWidth + 'px' }">
              <div v-for="(snap, idx) in cve.snapshots" :key="idx" class="gantt-bar snapshot-bar"
                :style="getSnapshotBarStyle(cve, idx)" :class="getSnapshotBarClass(cve, idx)"
                @mouseenter="handleBarMouseEnter(snap, cve, $event)" @mousemove="handleBarMouseMove($event)"
                @mouseleave="handleBarMouseLeave">
                <span class="bar-label">{{ getSnapshotStatusLabel(cve, idx) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="totalPages > 1" class="gantt-pagination">
        <button class="page-btn" :disabled="currentPage === 1" @click="currentPage--">Anterior</button>
        <span class="page-info">Pagina {{ currentPage }} de {{ totalPages }} ({{ cveSnapshots.length }} CVEs)</span>
        <button class="page-btn" :disabled="currentPage === totalPages" @click="currentPage++">Siguiente</button>
      </div>

      <!-- Tooltip -->
      <div v-if="isHovering && hoveredSnapshot" ref="tooltipRef" class="gantt-tooltip"
        :style="{ left: tooltipPos.x + 'px', top: tooltipPos.y + 'px' }">
        <div class="tooltip-header">{{ hoveredSnapshot.cve_id }}</div>
        <div class="tooltip-sync">Sincronización: {{ formatDate(hoveredSnapshot.syncTimestamp) }}</div>
        <div class="tooltip-agents">
          <div v-for="agent in hoveredSnapshot.agents" :key="agent" class="tooltip-agent">
            {{ agent }}
          </div>
        </div>
        <div class="tooltip-count">{{ hoveredSnapshot.agentCount }} agente{{ hoveredSnapshot.agentCount > 1 ? 's' : ''
        }} afectado{{ hoveredSnapshot.agentCount > 1 ? 's' : '' }}</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { parseServerDate } from '../timelineFormatters'

const props = defineProps({
  ganttData: { type: Array, default: () => null }
})

const ITEMS_PER_PAGE = 20
const currentPage = ref(1)

// Preserve full datetime — use parseServerDate for correct UTC handling
const toLocalDate = (d) => {
  if (!d) return new Date()
  if (d instanceof Date) return d
  return parseServerDate(d) || new Date()
}

// ── DEMO SNAPSHOTS (replaces old DEMO_DATA) ──
const DEMO_SNAPSHOTS = [
  {
    cve_id: 'CVE-2026-0001',
    severity: 'CRITICAL',
    description: 'RCE en modulo de autenticacion (DEMO)',
    snapshots: [
      { syncTimestamp: new Date(2026, 2, 1).toISOString(), agents: ['srv-web-01', 'srv-db-02', 'srv-api-03'], agentCount: 3 },
      { syncTimestamp: new Date(2026, 3, 1).toISOString(), agents: ['srv-web-01', 'srv-db-02'], agentCount: 2 },
      { syncTimestamp: new Date(2026, 4, 1).toISOString(), agents: ['srv-web-01'], agentCount: 1 }
    ],
    firstSync: new Date(2026, 2, 1).toISOString(),
    lastSync: new Date(2026, 4, 1).toISOString(),
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0002',
    severity: 'HIGH',
    description: 'SQL Injection en API REST (DEMO)',
    snapshots: [
      { syncTimestamp: new Date(2026, 2, 15).toISOString(), agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 },
      { syncTimestamp: new Date(2026, 3, 15).toISOString(), agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 },
      { syncTimestamp: new Date(2026, 4, 15).toISOString(), agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 }
    ],
    firstSync: new Date(2026, 2, 15).toISOString(),
    lastSync: new Date(2026, 4, 15).toISOString(),
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0003',
    severity: 'MEDIUM',
    description: 'XSS reflejado en dashboard (DEMO)',
    snapshots: [
      { syncTimestamp: new Date(2026, 1, 1).toISOString(), agents: ['srv-app-04'], agentCount: 1 },
      { syncTimestamp: new Date(2026, 2, 1).toISOString(), agents: ['srv-app-04', 'srv-web-03'], agentCount: 2 },
      { syncTimestamp: new Date(2026, 3, 1).toISOString(), agents: [], agentCount: 0 },
      { syncTimestamp: new Date(2026, 4, 1).toISOString(), agents: ['srv-app-04', 'srv-web-03', 'srv-db-01'], agentCount: 3 }
    ],
    firstSync: new Date(2026, 1, 1).toISOString(),
    lastSync: new Date(2026, 4, 1).toISOString(),
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0004',
    severity: 'LOW',
    description: 'Info disclosure en header HTTP (DEMO)',
    snapshots: [
      { syncTimestamp: new Date(2026, 0, 10).toISOString(), agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: new Date(2026, 1, 10).toISOString(), agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: new Date(2026, 2, 10).toISOString(), agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: new Date(2026, 3, 10).toISOString(), agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: new Date(2026, 4, 10).toISOString(), agents: [], agentCount: 0 }
    ],
    firstSync: new Date(2026, 0, 10).toISOString(),
    lastSync: new Date(2026, 4, 10).toISOString(),
    isResolved: true
  },
  {
    cve_id: 'CVE-2026-0005',
    severity: 'CRITICAL',
    description: 'Desbordamiento de buffer en servicio DHCP (DEMO)',
    snapshots: [
      { syncTimestamp: new Date(2026, 3, 5).toISOString(), agents: ['srv-dhcp-01', 'srv-dhcp-02', 'srv-dhcp-03', 'srv-dhcp-04', 'srv-dhcp-05'], agentCount: 5 }
    ],
    firstSync: new Date(2026, 3, 5).toISOString(),
    lastSync: new Date(2026, 3, 5).toISOString(),
    isResolved: false
  }
]

// ── Build CVEs with snapshots from real vuln data ──
const buildCveSnapshots = (vulns) => {
  // Group by cve_id
  const cveMap = new Map()

  vulns.forEach(v => {
    if (!cveMap.has(v.cve_id)) {
      cveMap.set(v.cve_id, {
        cve_id: v.cve_id,
        severity: v.severity || 'MEDIUM',
        description: v.description || '',
        agents: [],
        snapshots: [],
        isResolved: false
      })
    }
    const cve = cveMap.get(v.cve_id)
    cve.agents.push({
      agent_name: v.agent_name || 'unknown',
      agent_id: v.agent_id || '',
      first_seen: v.first_seen,
      last_seen: v.last_seen, // sync timestamp — same across machines
      history: v.historySorted || []
    })
  })

  // For each CVE, collect timestamps and build snapshots
  cveMap.forEach((cve) => {
    const timestampMap = new Map() // timestamp → Set of agent_names

    cve.agents.forEach(agent => {
      const addTimestamp = (ts) => {
        if (!ts) return
        if (!timestampMap.has(ts)) timestampMap.set(ts, new Set())
        timestampMap.get(ts).add(agent.agent_name)
      }

      addTimestamp(agent.first_seen)
      addTimestamp(agent.last_seen)  // sync timestamp — shared across machines
      agent.history.forEach(h => addTimestamp(h.timestamp))
    })

    const sortedTimestamps = Array.from(timestampMap.keys()).sort(
      (a, b) => new Date(a).getTime() - new Date(b).getTime()
    )

    cve.snapshots = sortedTimestamps.map(ts => ({
      syncTimestamp: ts,
      agents: Array.from(timestampMap.get(ts) || []),
      agentCount: (timestampMap.get(ts) || new Set()).size,
      cve_id: cve.cve_id
    }))

    // Resolved when all agents have a RESOLVED as their last history event
    cve.isResolved = cve.agents.length > 0 && cve.agents.every(agent => {
      const lastEvent = agent.history[agent.history.length - 1]
      return lastEvent && lastEvent.action === 'RESOLVED'
    })

    cve.firstSync = cve.snapshots[0]?.syncTimestamp || null
    cve.lastSync = cve.snapshots[cve.snapshots.length - 1]?.syncTimestamp || null
  })

  return Array.from(cveMap.values())
}

// ── Core computed: CVEs with sync snapshots ──
const cveSnapshots = computed(() => {
  const data = props.ganttData
  if (!data || data.length === 0) return DEMO_SNAPSHOTS
  const cves = buildCveSnapshots(data)
  // Merge nearby snapshots based on zoom level to avoid overlapping bars
  cves.forEach(cve => {
    cve.snapshots = mergeSnapshotsByZoom(cve.snapshots)
    cve.firstSync = cve.snapshots[0]?.syncTimestamp || null
    cve.lastSync = cve.snapshots[cve.snapshots.length - 1]?.syncTimestamp || null
  })
  return cves
})

// ── Pagination ──
const totalPages = computed(() => Math.max(1, Math.ceil(cveSnapshots.value.length / ITEMS_PER_PAGE)))

const paginatedCveSnapshots = computed(() => {
  const start = (currentPage.value - 1) * ITEMS_PER_PAGE
  return cveSnapshots.value.slice(start, start + ITEMS_PER_PAGE)
})

watch(() => props.ganttData, () => {
  currentPage.value = 1
})

// ── Scroll / Search ──
const scrollWrapper = ref(null)
const searchDate = ref('')
const showDatePicker = ref(false)
const datePopupRef = ref(null)

const MONTHS = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic']

const now = new Date()
const pickerYear = ref(now.getFullYear())
const pickerMonth = ref(now.getMonth())
const pickerDay = ref(now.getDate())
const pickerHour = ref('00')
const pickerMinute = ref('00')

const years = computed(() => {
  const y = []
  for (let i = now.getFullYear() - 5; i <= now.getFullYear() + 2; i++) y.push(i)
  return y
})

const daysInMonth = computed(() => {
  const days = new Date(pickerYear.value, pickerMonth.value + 1, 0).getDate()
  return Array.from({ length: days }, (_, i) => i + 1)
})

const formattedSearchDate = computed(() => {
  if (!searchDate.value) return ''
  const d = new Date(searchDate.value)
  if (isNaN(d.getTime())) return searchDate.value
  const dd = String(d.getDate()).padStart(2, '0')
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const min = String(d.getMinutes()).padStart(2, '0')
  return `${dd}/${mm}/${d.getFullYear()} ${hh}:${min}`
})

const toggleDatePicker = () => {
  if (showDatePicker.value) {
    showDatePicker.value = false
    return
  }
  // Parse current searchDate into picker values
  if (searchDate.value) {
    const d = new Date(searchDate.value)
    if (!isNaN(d.getTime())) {
      pickerYear.value = d.getFullYear()
      pickerMonth.value = d.getMonth()
      pickerDay.value = d.getDate()
      pickerHour.value = String(d.getHours()).padStart(2, '0')
      pickerMinute.value = String(d.getMinutes()).padStart(2, '0')
    }
  }
  showDatePicker.value = true
}

const applyPickerDate = () => {
  const hh = pickerHour.value.padStart(2, '0')
  const min = pickerMinute.value.padStart(2, '0')
  const mm = String(pickerMonth.value + 1).padStart(2, '0')
  const dd = String(pickerDay.value).padStart(2, '0')
  searchDate.value = `${pickerYear.value}-${mm}-${dd}T${hh}:${min}`
  showDatePicker.value = false
}

// Close picker when clicking outside
const handleClickOutside = (e) => {
  if (datePopupRef.value && !datePopupRef.value.contains(e.target) && !e.target.closest('.date-trigger')) {
    showDatePicker.value = false
  }
}

onMounted(() => document.addEventListener('click', handleClickOutside))
onUnmounted(() => document.removeEventListener('click', handleClickOutside))

const scrollToDate = () => {
  if (!searchDate.value || !scrollWrapper.value || !timeLabels.value.length) return

  const targetDate = new Date(searchDate.value)
  const startMs = timeLabels.value[0].date.getTime()
  const totalPx = timelineWidth.value
  const rangeMs = (timeLabels.value.length - 1) * msPerUnit.value

  if (rangeMs <= 0) return

  const msFromStart = targetDate.getTime() - startMs
  const scrollPos = (msFromStart / rangeMs) * totalPx

  scrollWrapper.value.scrollTo({ left: Math.max(0, scrollPos - 200), behavior: 'smooth' })
}

// ── Zoom ──
const ZOOM_LEVELS = [
  { label: 'Año', unit: 'year', width: 80 },
  { label: 'Mes', unit: 'month', width: 100 },
  { label: 'Dia', unit: 'day', width: 50 },
  { label: 'Hora', unit: 'hour', width: 40 }
]

const zoomIndex = ref(1)
const zoomLevel = computed(() => ZOOM_LEVELS[zoomIndex.value])
const zoomLabel = computed(() => zoomLevel.value.label)

const zoomIn = () => { if (zoomIndex.value < ZOOM_LEVELS.length - 1) zoomIndex.value++ }
const zoomOut = () => { if (zoomIndex.value > 0) zoomIndex.value-- }

const MONTH_WIDTH = computed(() => zoomLevel.value.width)
const MIN_BAR_WIDTH = 3

// ── Zoom-aware snapshot merging threshold ──
const MIN_SNAP_GAP_MS = computed(() => {
  const unit = zoomLevel.value.unit
  if (unit === 'year') return 7 * 86400000  // semanal en vista año
  if (unit === 'month') return 86400000      // diario en vista mes
  if (unit === 'day') return 3600000         // cada hora en vista día
  return 600000                               // 10 min en vista hora
})

/** Merge snapshots whose timestamps are closer than MIN_SNAP_GAP_MS.
 *  Keeps the earliest timestamp, unions agent sets. */
const mergeSnapshotsByZoom = (snapshots) => {
  if (snapshots.length <= 1) return snapshots
  const merged = []
  let current = { ...snapshots[0] }

  for (let i = 1; i < snapshots.length; i++) {
    const gap = new Date(snapshots[i].syncTimestamp).getTime() - new Date(current.syncTimestamp).getTime()
    if (gap < MIN_SNAP_GAP_MS.value) {
      // Merge: union agents, keep earlier timestamp
      const agentSet = new Set([...current.agents, ...snapshots[i].agents])
      current = {
        ...current,
        agents: Array.from(agentSet),
        agentCount: agentSet.size,
      }
    } else {
      merged.push(current)
      current = { ...snapshots[i] }
    }
  }
  merged.push(current)
  return merged
}

// ── Time labels: extracted helpers ──
const generateYearLabels = (start, end) => {
  const labels = []
  let current = new Date(start.getFullYear(), 0, 1)
  const minEnd = new Date(start.getFullYear() + 2, 0, 1)
  const effectiveEnd = end > minEnd ? end : minEnd
  while (current <= effectiveEnd) {
    labels.push({ label: current.getFullYear().toString(), date: new Date(current) })
    current = new Date(current.getFullYear() + 1, 0, 1)
  }
  return labels
}

const generateMonthLabels = (start, end) => {
  const labels = []
  const spansMultipleYears = end.getFullYear() > start.getFullYear()
  let current = new Date(start.getFullYear(), start.getMonth(), 1)
  while (current <= end) {
    const label = spansMultipleYears
      ? current.toLocaleString('es', { month: 'short', year: '2-digit' })
      : current.toLocaleString('es', { month: 'short' })
    labels.push({ label, date: new Date(current) })
    current = new Date(current.getFullYear(), current.getMonth() + 1, 1)
  }
  // Push one extra label past end for timeline buffer
  const extraLabel = spansMultipleYears
    ? current.toLocaleString('es', { month: 'short', year: '2-digit' })
    : current.toLocaleString('es', { month: 'short' })
  labels.push({ label: extraLabel, date: new Date(current) })
  return labels
}

const generateDayLabels = (start, end) => {
  const labels = []
  const spansMultipleYears = end.getFullYear() > start.getFullYear()
  let current = new Date(start.getFullYear(), start.getMonth(), start.getDate())
  while (current <= end) {
    const label = spansMultipleYears
      ? current.toLocaleString('es', { day: '2-digit', month: 'short', year: '2-digit' })
      : current.toLocaleString('es', { day: '2-digit', month: 'short' })
    labels.push({ label, date: new Date(current) })
    current = new Date(current.getFullYear(), current.getMonth(), current.getDate() + 1)
  }
  // Push one extra label past end for timeline buffer
  const extraLabel = spansMultipleYears
    ? current.toLocaleString('es', { day: '2-digit', month: 'short', year: '2-digit' })
    : current.toLocaleString('es', { day: '2-digit', month: 'short' })
  labels.push({ label: extraLabel, date: new Date(current) })
  return labels
}

const generateHourLabels = (start, end) => {
  const labels = []
  const spansMultipleDays = Math.ceil((end - start) / (24 * 60 * 60 * 1000)) >= 1
  let current = new Date(start.getFullYear(), start.getMonth(), start.getDate(), start.getHours(), 0, 0)
  while (current <= end) {
    const label = spansMultipleDays
      ? current.toLocaleString('es', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
      : current.toLocaleString('es', { hour: '2-digit', minute: '2-digit', hour12: false })
    labels.push({ label, date: new Date(current) })
    current = new Date(current.getFullYear(), current.getMonth(), current.getDate(), current.getHours() + 1, 0, 0)
  }
  // Push one extra label past end for timeline buffer
  const extraLabel = spansMultipleDays
    ? current.toLocaleString('es', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
    : current.toLocaleString('es', { hour: '2-digit', minute: '2-digit', hour12: false })
  labels.push({ label: extraLabel, date: new Date(current) })
  return labels
}

// ── Time labels & timeline dimensions ──
const timeLabels = computed(() => {
  if (!cveSnapshots.value.length) return []

  // Find min/max dates from all snapshot timestamps
  let minMs = Infinity
  let maxMs = -Infinity
  cveSnapshots.value.forEach(cve => {
    cve.snapshots.forEach(snap => {
      const t = toLocalDate(snap.syncTimestamp).getTime()
      if (t < minMs) minMs = t
      if (t > maxMs) maxMs = t
    })
  })
  if (minMs === Infinity) return []

  const start = new Date(minMs)
  const end = new Date(Math.max(maxMs, Date.now()))
  const unit = zoomLevel.value.unit

  switch (unit) {
    case 'year': return generateYearLabels(start, end)
    case 'month': return generateMonthLabels(start, end)
    case 'day': return generateDayLabels(start, end)
    case 'hour': return generateHourLabels(start, end)
    default: return []
  }
})

// Calculate ms per unit for accurate positioning
const msPerUnit = computed(() => {
  const unit = zoomLevel.value.unit
  if (unit === 'year') return 365.25 * 24 * 60 * 60 * 1000
  if (unit === 'month') return 30.44 * 24 * 60 * 60 * 1000
  if (unit === 'day') return 24 * 60 * 60 * 1000
  return 60 * 60 * 1000
})

const timelineWidth = computed(() => {
  const count = timeLabels.value.length
  if (count <= 1) return MONTH_WIDTH.value
  return (count - 1) * MONTH_WIDTH.value
})

// ── Snapshot bar style: position + width for each sync segment ──
const getSnapshotBarStyle = (cve, idx) => {
  if (!timeLabels.value.length) return {}
  const totalPx = timelineWidth.value
  const startMs = timeLabels.value[0].date.getTime()
  const rangeMs = (timeLabels.value.length - 1) * msPerUnit.value
  if (rangeMs <= 0) return {}

  const snap = cve.snapshots[idx]
  const snapDate = toLocalDate(snap.syncTimestamp)
  const leftPx = ((snapDate.getTime() - startMs) / rangeMs) * totalPx

  // Bar ends at next snapshot or now for the last one
  const nextSnap = cve.snapshots[idx + 1]
  const endDate = nextSnap ? toLocalDate(nextSnap.syncTimestamp) : new Date()
  const widthPx = ((endDate.getTime() - snapDate.getTime()) / rangeMs) * totalPx

  return {
    left: `${Math.max(leftPx, 0)}px`,
    width: `${Math.max(widthPx, MIN_BAR_WIDTH)}px`
  }
}

// ── Snapshot bar class by status (detected / reopened / resolved) ──
const getSnapshotBarClass = (cve, idx) => {
  const snap = cve.snapshots[idx]
  if (snap.agentCount === 0) return 'snap-resolved'
  if (idx > 0 && cve.snapshots[idx - 1].agentCount === 0) return 'snap-reopened'
  return 'snap-detected'
}

const getSnapshotStatusLabel = (cve, idx) => {
  const snap = cve.snapshots[idx]
  if (snap.agentCount === 0) return 'Resuelto'
  if (idx > 0 && cve.snapshots[idx - 1].agentCount === 0) return 'Reabierto'
  return 'Activo'
}

// ── Tooltip state ──
const hoveredSnapshot = ref(null)
const tooltipPos = ref({ x: 0, y: 0 })
const isHovering = ref(false)
const tooltipRef = ref(null)

const handleBarMouseEnter = (snapshot, cve, event) => {
  isHovering.value = true
  hoveredSnapshot.value = {
    ...snapshot,
    cve_id: cve.cve_id,
    syncTimestamp: snapshot.syncTimestamp,
  }
  // Set preliminary position immediately, refine after render
  tooltipPos.value = { x: event.clientX + 12, y: event.clientY - 10 }
  nextTick(() => refineTooltipPos(event))
}

const handleBarMouseMove = (event) => {
  updateTooltipPos(event)
  nextTick(() => refineTooltipPos(event))
}

const handleBarMouseLeave = () => {
  isHovering.value = false
  hoveredSnapshot.value = null
}

const updateTooltipPos = (event) => {
  tooltipPos.value = { x: event.clientX + 12, y: event.clientY - 10 }
}

const refineTooltipPos = (event) => {
  if (!tooltipRef.value) return

  const tooltipHeight = tooltipRef.value.offsetHeight
  const tooltipWidth = tooltipRef.value.offsetWidth
  let x = event.clientX + 12
  let y = event.clientY - 10

  // Flip above cursor if it overflows the bottom
  if (y + tooltipHeight > window.innerHeight - 8) {
    y = event.clientY - tooltipHeight - 12
  }
  // Keep above viewport top
  if (y < 8) y = 8

  // Flip left if it overflows right edge
  if (x + tooltipWidth > window.innerWidth - 8) {
    x = event.clientX - tooltipWidth - 12
  }

  tooltipPos.value = { x, y }
}

// ── Helpers ──
const formatDate = (d) => {
  if (!d) return '-'
  const date = toLocalDate(d)
  return date.toLocaleDateString('es-CL', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
</script>

<style scoped>
.gantt-card {
  background: var(--surface, #ffffff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: var(--radius-lg, 8px);
  overflow: hidden;
  min-width: 0;
  position: relative;
}

.gantt-header {
  padding: 0.75rem 1rem;
  background: var(--surface-container-high, #f1f5f9);
  border-bottom: 1px solid var(--border, #e2e8f0);
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.gantt-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
}

.search-date {
  display: flex;
  gap: 4px;
  align-items: center;
  position: relative;
}

.date-trigger {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  cursor: pointer;
  height: 26px;
  min-width: 120px;
}

.date-trigger:hover {
  border-color: #3d6a00;
}

.cal-icon {
  font-size: 12px;
}

.date-popup {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  z-index: 100;
  background: white;
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.12);
  padding: 8px;
  min-width: 200px;
}

.popup-row {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-bottom: 6px;
}

.popup-sel {
  padding: 3px 4px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  cursor: pointer;
  height: 26px;
}

.popup-sel.time-sel {
  width: 50px;
}

.time-sep {
  font-size: 12px;
  font-weight: 700;
  color: #64748b;
}

.popup-actions {
  display: flex;
  justify-content: flex-end;
  gap: 6px;
  border-top: 1px solid #e2e8f0;
  padding-top: 6px;
  margin-top: 2px;
}

.popup-btn {
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  border: 1px solid #cbd5e1;
  background: white;
  color: #64748b;
}

.popup-btn.cancel:hover {
  background: #f1f5f9;
}

.popup-btn.apply {
  background: #3d6a00;
  border-color: #3d6a00;
  color: white;
}

.popup-btn.apply:hover {
  background: #2d5000;
}

.search-date-label {
  font-size: 11px;
  color: #64748b;
  font-weight: 600;
}

.gantt-loading-state,
.gantt-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 1rem;
  color: #64748b;
  font-size: 0.9rem;
  gap: 1rem;
}

.gantt-spinner {
  width: 32px;
  height: 32px;
  border: 3px solid #e2e8f0;
  border-top-color: #3d6a00;
  border-radius: 50%;
  animation: gantt-spin 0.8s linear infinite;
}

@keyframes gantt-spin {
  to {
    transform: rotate(360deg);
  }
}

.search-btn {
  padding: 4px 12px;
  border: none;
  background: #3d6a00;
  color: white;
  font-size: 11px;
  font-weight: 600;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.15s;
}

.search-btn:hover {
  background: #2d5000;
}

.zoom-controls {
  display: flex;
  align-items: center;
  gap: 4px;
  background: #e2e8f0;
  border-radius: 4px;
  padding: 2px;
}

.zoom-btn {
  width: 24px;
  height: 24px;
  border: none;
  background: transparent;
  color: #64748b;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  border-radius: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}

.zoom-btn:hover {
  background: white;
  color: #0f172a;
}

.zoom-level {
  font-size: 10px;
  font-weight: 600;
  color: #334155;
  min-width: 32px;
  text-align: center;
}

.gantt-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text, #1e293b);
  margin: 0;
  white-space: nowrap;
}

.gantt-legend {
  display: flex;
  gap: 0.75rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.8rem;
  color: var(--text-muted, #64748b);
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.legend-dot.snap-detected {
  background-color: #ba1a1a;
}

.legend-dot.snap-reopened {
  background-color: #ca8a04;
}

.legend-dot.snap-resolved {
  background-color: #6ca42c;
}

.gantt-scroll-wrapper {
  overflow-x: auto;
  overflow-y: hidden;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.gantt-header-row {
  display: flex;
  background: #f8fafc;
  border-bottom: 1px solid #e2e8f0;
  height: 36px;
  flex-shrink: 0;
}

.gantt-sidebar-header {
  width: 260px;
  flex-shrink: 0;
  padding: 0 10px;
  display: flex;
  align-items: center;
  font-weight: 700;
  font-size: 10px;
  color: #64748b;
  text-transform: uppercase;
  border-right: 1px solid #e2e8f0;
}

.gantt-timeline-header {
  display: flex;
}

.month-label {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 600;
  color: #64748b;
  border-right: 1px dashed #e2e8f0;
  flex-shrink: 0;
}

.gantt-body {
  display: flex;
  flex-direction: column;
}

.gantt-row {
  display: flex;
  min-width: fit-content;
}

.gantt-row.cve-row {
  height: 32px;
  border-bottom: 1px solid #e2e8f0;
  flex-shrink: 0;
  transition: background 0.15s ease;
}

.gantt-row.cve-row:hover {
  background: #f8fafc;
}

.gantt-sidebar-cell {
  width: 260px;
  flex-shrink: 0;
  padding: 4px 10px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  border-right: 1px solid #e2e8f0;
  overflow: hidden;
}

.cve-top {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 2px;
}

.cve-id {
  font-family: monospace;
  font-size: 11px;
  font-weight: 700;
  color: #0f172a;
}

.cve-desc {
  font-size: 10px;
  color: #64748b;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 1px;
}

.cve-sync-count {
  font-size: 9px;
  color: #94a3b8;
  font-weight: 500;
}

.sev-badge {
  font-size: 9px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 3px;
  text-transform: uppercase;
}

.sev-badge.critical {
  background: #fee2e2;
  color: #991b1b;
}

.sev-badge.high {
  background: #ffedd5;
  color: #9a3412;
}

.sev-badge.medium {
  background: #dbeafe;
  color: #1e40af;
}

.sev-badge.low {
  background: #dcfce7;
  color: #166534;
}

.gantt-chart-cell {
  position: relative;
  flex-shrink: 0;
  height: 32px;
}

.gantt-bar {
  position: absolute;
  height: calc(100% - 6px);
  top: 3px;
  border-radius: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  z-index: 0;
  cursor: pointer;
  transition: opacity 0.1s ease;
}

.gantt-bar:hover {
  opacity: 0.85;
  z-index: 1;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.15);
}

/* Snapshot bar colors by status */
.gantt-bar.snap-detected {
  background-color: rgba(186, 26, 26, 0.2);
  border: 1px solid #ba1a1a;
}

.gantt-bar.snap-reopened {
  background-color: rgba(234, 179, 8, 0.2);
  border: 1px solid #ca8a04;
}

.gantt-bar.snap-resolved {
  background-color: rgba(108, 164, 44, 0.25);
  border: 1px solid #6ca42c;
}

.bar-label {
  font-size: 9px;
  font-weight: 600;
  white-space: nowrap;
}

.gantt-pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  padding: 0.75rem;
  border-top: 1px solid var(--border, #e2e8f0);
  background: var(--surface-container-low, #f8fafc);
}

.page-btn {
  padding: 0.4rem 0.8rem;
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 4px;
  background: white;
  color: var(--text, #1e293b);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
}

.page-btn:hover:not(:disabled) {
  background: var(--primary-bg, #e8f5e9);
  border-color: var(--primary, #3d6a00);
}

.page-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-info {
  font-size: 0.85rem;
  color: var(--text-muted, #64748b);
}

/* ── Tooltip ── */
.gantt-tooltip {
  position: fixed;
  z-index: 9999;
  background: var(--bg-card, #ffffff);
  color: var(--text-main, #111827);
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.5;
  max-width: 260px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
  pointer-events: none;
  border: 1px solid var(--border, #e5e7eb);
}

.tooltip-header {
  font-weight: 700;
  font-size: 13px;
  margin-bottom: 4px;
  color: var(--text-main, #111827);
  font-family: monospace;
}

.tooltip-sync {
  font-size: 11px;
  color: var(--text-muted, #6b7280);
  margin-bottom: 6px;
}

.tooltip-agents {
  max-height: 120px;
  overflow-y: auto;
  margin-bottom: 4px;
}

.tooltip-agent {
  font-family: monospace;
  font-size: 11px;
  color: var(--text-main, #111827);
  padding: 1px 0;
}

.tooltip-agent::before {
  content: '•';
  color: #6b7280;
  margin-right: 4px;
}

.tooltip-count {
  font-size: 11px;
  font-weight: 700;
  padding-top: 4px;
  border-top: 1px solid var(--border, #e5e7eb);
}
</style>
