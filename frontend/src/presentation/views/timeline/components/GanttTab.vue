<template>
  <div class="card gantt-card">
    <div class="gantt-header">
      <h3 class="gantt-title">Seguimiento de CVEs Criticos</h3>
      <div class="gantt-controls">
        <div class="search-date">
          <input type="datetime-local" v-model="searchDate" class="date-input" />
          <button class="search-btn" @click="scrollToDate">Ir</button>
        </div>
        <div class="zoom-controls">
          <button class="zoom-btn" @click="zoomOut" title="Alejar">-</button>
          <span class="zoom-level">{{ zoomLabel }}</span>
          <button class="zoom-btn" @click="zoomIn" title="Acercar">+</button>
        </div>
        <div class="gantt-legend">
          <div class="legend-item"><span class="legend-dot pending"></span> Pendiente</div>
          <div class="legend-item"><span class="legend-dot resolved"></span> Resuelto</div>
          <div class="legend-item"><span class="legend-dot reopened"></span> Reabierto</div>
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
        <template v-for="cveGroup in groupedByCve" :key="cveGroup.cve_id">
          <!-- CVE header row -->
          <div class="cve-header-row">
            <div class="cve-header-sidebar">
              <span class="cve-id">{{ cveGroup.cve_id }}</span>
              <span class="sev-badge" :class="cveGroup.severity.toLowerCase()">{{ cveGroup.severity }}</span>
              <span v-if="cveGroup.reopenCount > 0" class="reopen-badge"
                :title="`Reactivado ${cveGroup.reopenCount} vez${cveGroup.reopenCount > 1 ? 'es' : ''}`">
                ↻ {{ cveGroup.reopenCount }}
              </span>
              <span class="cve-agent-count">{{ cveGroup.agents.length }} agente{{ cveGroup.agents.length > 1 ? 's' : ''
                }}</span>
            </div>
            <div class="cve-header-chart" :style="{ minWidth: timelineWidth + 'px' }"></div>
          </div>
          <!-- Agent rows -->
          <div v-for="agent in cveGroup.agents" :key="agent.key" class="gantt-row agent-row"
            :style="{ height: getRowHeight(agent.laneCount) + 'px' }">
            <div class="gantt-sidebar-cell">
              <div class="agent-top">
                <span class="agent-name" :title="agent.agent_name || 'Sin nombre'">{{ agent.agent_name || 'Desconocido'
                  }}</span>
              </div>
              <span class="cve-desc">{{ agent.description }}</span>
              <div class="cve-dates-inline">
                <span class="date-chip detected">Det: {{ formatDate(agent.first_seen) }}</span>
                <span v-if="agent.resolved_at" class="date-chip resolved">Res: {{ formatDate(agent.resolved_at)
                  }}</span>
                <span v-if="agent.reopened_at" class="date-chip reopened">Rea: {{ formatDate(agent.reopened_at)
                  }}</span>
              </div>
            </div>
            <div class="gantt-chart-cell" :style="{ minWidth: timelineWidth + 'px' }">
              <div v-for="(seg, idx) in agent.segments" :key="idx" class="gantt-bar" :style="getBarStyle(seg)"
                :class="seg.status.toLowerCase()">
                <span class="bar-label" :class="{ visible: seg._barWidthPx > 40 }">
                  {{ seg.status === 'PENDING' ? 'Activo' : (seg.status === 'REOPENED' ? 'Reabierto' : 'Resuelto') }}
                </span>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>

    <div v-if="totalPages > 1" class="gantt-pagination">
      <button class="page-btn" :disabled="currentPage === 1" @click="currentPage--">Anterior</button>
      <span class="page-info">Pagina {{ currentPage }} de {{ totalPages }} ({{ totalAgentRows }} filas)</span>
      <button class="page-btn" :disabled="currentPage === totalPages" @click="currentPage++">Siguiente</button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import * as d3 from 'd3'

const props = defineProps({
  ganttData: { type: Array, required: true }
})

const ITEMS_PER_PAGE = 20
const currentPage = ref(1)

// Preserve full datetime — do NOT strip time component
const toLocalDate = (d) => {
  if (!d) return new Date()
  if (d instanceof Date) return d
  // Handle ISO strings like '2024-01-10T14:30:00Z' or '2024-01-10'
  const dateStr = d.split('T')[0]
  const parts = dateStr.split('-')
  const base = new Date(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]))
  // Preserve time if present in the original string
  if (d.includes('T')) {
    const timePart = d.split('T')[1]
    if (timePart) {
      const [hms] = timePart.split(/[Z+-]/)
      const [h, m, s] = hms.split(':').map(Number)
      base.setHours(h || 0, m || 0, s || 0, 0)
    }
  }
  return base
}

const displaySegments = computed(() => {
  // Demo data to visualize all states (resolved, reopened, pending) with multiple agents
  // Remove this block when real data covers all scenarios
  const DEMO_DATA = [
    {
      cve_id: 'CVE-2026-0001', severity: 'CRITICAL', description: 'RCE en modulo de autenticacion (DEMO)',
      agent_name: 'srv-web-01', agent_id: 'demo-001',
      first_seen: new Date(2026, 3, 1).toISOString(),
      history: [
        { action: 'RESOLVED', timestamp: new Date(2026, 3, 15).toISOString() },
        { action: 'REOPENED', timestamp: new Date(2026, 4, 1).toISOString() },
        { action: 'RESOLVED', timestamp: new Date(2026, 4, 10).toISOString() }
      ]
    },
    {
      cve_id: 'CVE-2026-0001', severity: 'CRITICAL', description: 'RCE en modulo de autenticacion (DEMO)',
      agent_name: 'srv-db-02', agent_id: 'demo-002',
      first_seen: new Date(2026, 3, 5).toISOString(),
      history: [
        { action: 'RESOLVED', timestamp: new Date(2026, 3, 20).toISOString() }
      ]
    },
    {
      cve_id: 'CVE-2026-0001', severity: 'CRITICAL', description: 'RCE en modulo de autenticacion (DEMO)',
      agent_name: 'srv-api-03', agent_id: 'demo-003',
      first_seen: new Date(2026, 4, 1).toISOString(),
      history: []
    },
    {
      cve_id: 'CVE-2026-0002', severity: 'HIGH', description: 'SQL Injection en API REST (DEMO)',
      agent_name: 'srv-web-01', agent_id: 'demo-004',
      first_seen: new Date(2026, 4, 5).toISOString(),
      history: [
        { action: 'RESOLVED', timestamp: new Date(2026, 4, 12).toISOString() },
        { action: 'REOPENED', timestamp: new Date(2026, 4, 14).toISOString() }
      ]
    },
    {
      cve_id: 'CVE-2026-0003', severity: 'MEDIUM', description: 'XSS reflejado en dashboard (DEMO)',
      agent_name: 'srv-app-04', agent_id: 'demo-005',
      first_seen: new Date(2026, 2, 20).toISOString(),
      history: [
        { action: 'RESOLVED', timestamp: new Date(2026, 3, 1).toISOString() }
      ]
    },
    {
      cve_id: 'CVE-2026-0004', severity: 'LOW', description: 'Info disclosure en header HTTP (DEMO)',
      agent_name: 'srv-proxy-05', agent_id: 'demo-006',
      first_seen: new Date(2026, 1, 10).toISOString(),
      history: [
        { action: 'RESOLVED', timestamp: new Date(2026, 2, 1).toISOString() },
        { action: 'REOPENED', timestamp: new Date(2026, 2, 15).toISOString() },
        { action: 'RESOLVED', timestamp: new Date(2026, 3, 1).toISOString() },
        { action: 'REOPENED', timestamp: new Date(2026, 4, 1).toISOString() },
        { action: 'RESOLVED', timestamp: new Date(2026, 4, 15).toISOString() }
      ]
    }
  ]

  const allData = [...DEMO_DATA, ...props.ganttData]
  if (!allData || allData.length === 0) return []

  const segments = []
  const now = new Date()

  allData.forEach(v => {
    const history = (v.history || [])
      .filter(h => h.action === 'RESOLVED' || h.action === 'REOPENED')
      .sort((a, b) => toLocalDate(a.timestamp) - toLocalDate(b.timestamp))

    let currentStart = toLocalDate(v.first_seen)
    let currentState = 'PENDING'

    if (history.length === 0) {
      segments.push({
        cve_id: v.cve_id, severity: v.severity, description: v.description,
        agent_name: v.agent_name, agent_id: v.agent_id,
        start: currentStart, end: now, status: 'PENDING', agents: v.agents || 0,
        first_seen: v.first_seen, resolved_at: null, reopened_at: null, reopenCount: 0
      })
      return
    }

    let reopenCount = 0
    history.forEach(event => {
      const eventDate = toLocalDate(event.timestamp)
      if (event.action === 'RESOLVED') {
        segments.push({
          cve_id: v.cve_id, severity: v.severity, description: v.description,
          agent_name: v.agent_name, agent_id: v.agent_id,
          start: currentStart, end: eventDate, status: currentState, agents: v.agents || 0,
          first_seen: v.first_seen, resolved_at: event.timestamp, reopened_at: null, reopenCount: 0
        })
        currentState = 'RESOLVED'
        currentStart = eventDate
      } else if (event.action === 'REOPENED') {
        reopenCount++
        segments.push({
          cve_id: v.cve_id, severity: v.severity, description: v.description,
          agent_name: v.agent_name, agent_id: v.agent_id,
          start: currentStart, end: eventDate, status: currentState, agents: v.agents || 0,
          first_seen: v.first_seen, resolved_at: null, reopened_at: event.timestamp, reopenCount: 0
        })
        currentState = 'REOPENED'
        currentStart = eventDate
      }
    })

    segments.push({
      cve_id: v.cve_id, severity: v.severity, description: v.description,
      agent_name: v.agent_name, agent_id: v.agent_id,
      start: currentStart, end: now, status: currentState, agents: v.agents || 0,
      first_seen: v.first_seen, resolved_at: currentState === 'RESOLVED' ? history[history.length - 1]?.timestamp : null,
      reopened_at: currentState === 'REOPENED' ? history[history.length - 1]?.timestamp : null,
      reopenCount
    })
  })

  // Merge consecutive segments with the same status FOR THE SAME AGENT
  const merged = []
  for (const seg of segments) {
    const last = merged[merged.length - 1]
    const sameAgent = (last?.agent_name ?? '__none__') === (seg.agent_name ?? '__none__')
    const sameCve = last?.cve_id === seg.cve_id
    const sameStatus = last?.status === seg.status
    const consecutive = last && seg.start.getTime() <= last.end.getTime() + 1000 // 1s tolerance

    if (sameAgent && sameCve && sameStatus && consecutive) {
      last.end = seg.end > last.end ? seg.end : last.end
      last.resolved_at = seg.resolved_at || last.resolved_at
      last.reopened_at = seg.reopened_at || last.reopened_at
    } else {
      merged.push({ ...seg })
    }
  }

  return merged
})

const totalPages = computed(() => Math.ceil(displaySegments.value.length / ITEMS_PER_PAGE))

const totalAgentRows = computed(() => {
  return groupedByCve.value.reduce((sum, cve) => sum + cve.agents.length, 0)
})

const paginatedData = computed(() => {
  const start = (currentPage.value - 1) * ITEMS_PER_PAGE
  return displaySegments.value.slice(start, start + ITEMS_PER_PAGE)
})

watch(() => props.ganttData, () => {
  currentPage.value = 1
})

const scrollWrapper = ref(null)
const searchDate = ref('')

const scrollToDate = () => {
  if (!searchDate.value || !scrollWrapper.value || !timeLabels.value.length) return

  const targetDate = new Date(searchDate.value)
  const startMs = timeLabels.value[0].date.getTime()
  const totalPx = timelineWidth.value
  // The timeline range spans (count - 1) intervals between labels
  const rangeMs = (timeLabels.value.length - 1) * msPerUnit.value

  if (rangeMs <= 0) return

  const msFromStart = targetDate.getTime() - startMs
  const scrollPos = (msFromStart / rangeMs) * totalPx

  scrollWrapper.value.scrollTo({ left: Math.max(0, scrollPos - 200), behavior: 'smooth' })
}

const ZOOM_LEVELS = [
  { label: 'Año', unit: 'year', width: 80 },
  { label: 'Mes', unit: 'month', width: 100 },
  { label: 'Dia', unit: 'day', width: 50 },
  { label: 'Hora', unit: 'hour', width: 40 }
]

const zoomIndex = ref(1) // Start at month view
const zoomLevel = computed(() => ZOOM_LEVELS[zoomIndex.value])
const zoomLabel = computed(() => zoomLevel.value.label)

const zoomIn = () => { if (zoomIndex.value < ZOOM_LEVELS.length - 1) zoomIndex.value++ }
const zoomOut = () => { if (zoomIndex.value > 0) zoomIndex.value-- }

const MONTH_WIDTH = computed(() => zoomLevel.value.width)
const MIN_BAR_WIDTH = 3
const LANE_HEIGHT = 28

const timeLabels = computed(() => {
  if (!displaySegments.value.length) return []

  const start = d3.min(displaySegments.value, d => d.start)
  const end = new Date(Math.max(d3.max(displaySegments.value, d => d.end).getTime(), Date.now()))
  const unit = zoomLevel.value.unit

  const labels = []
  let current = new Date(start)

  if (unit === 'year') {
    current = new Date(start.getFullYear(), 0, 1)
    const minEnd = new Date(start.getFullYear() + 2, 0, 1)
    const effectiveEnd = end > minEnd ? end : minEnd
    while (current <= effectiveEnd) {
      labels.push({ label: current.getFullYear().toString(), date: new Date(current) })
      current = new Date(current.getFullYear() + 1, 0, 1)
    }
  } else if (unit === 'month') {
    current = new Date(start.getFullYear(), start.getMonth(), 1)
    const spansMultipleYears = end.getFullYear() > start.getFullYear()
    while (current <= end) {
      const label = spansMultipleYears
        ? current.toLocaleString('es', { month: 'short', year: '2-digit' })
        : current.toLocaleString('es', { month: 'short' })
      labels.push({ label, date: new Date(current) })
      current = new Date(current.getFullYear(), current.getMonth() + 1, 1)
    }
    // Add one extra month column to ensure active bars aren't cut off
    const label = spansMultipleYears
      ? current.toLocaleString('es', { month: 'short', year: '2-digit' })
      : current.toLocaleString('es', { month: 'short' })
    labels.push({ label, date: new Date(current) })
  } else if (unit === 'day') {
    current = new Date(start.getFullYear(), start.getMonth(), start.getDate())
    const spansMultipleYears = end.getFullYear() > start.getFullYear()
    while (current <= end) {
      const label = spansMultipleYears
        ? current.toLocaleString('es', { day: '2-digit', month: 'short', year: '2-digit' })
        : current.toLocaleString('es', { day: '2-digit', month: 'short' })
      labels.push({ label, date: new Date(current) })
      current = new Date(current.getFullYear(), current.getMonth(), current.getDate() + 1)
    }
    const label = spansMultipleYears
      ? current.toLocaleString('es', { day: '2-digit', month: 'short', year: '2-digit' })
      : current.toLocaleString('es', { day: '2-digit', month: 'short' })
    labels.push({ label, date: new Date(current) })
  } else if (unit === 'hour') {
    current = new Date(start.getFullYear(), start.getMonth(), start.getDate(), start.getHours(), 0, 0)
    const spansMultipleDays = Math.ceil((end - start) / (24 * 60 * 60 * 1000)) >= 1
    while (current <= end) {
      const label = spansMultipleDays
        ? current.toLocaleString('es', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
        : current.toLocaleString('es', { hour: '2-digit', minute: '2-digit', hour12: false })
      labels.push({ label, date: new Date(current) })
      current = new Date(current.getFullYear(), current.getMonth(), current.getDate(), current.getHours() + 1, 0, 0)
    }
    const label = spansMultipleDays
      ? current.toLocaleString('es', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
      : current.toLocaleString('es', { hour: '2-digit', minute: '2-digit', hour12: false })
    labels.push({ label, date: new Date(current) })
  }

  return labels
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
  // The range spans (count - 1) intervals between labels
  return (count - 1) * MONTH_WIDTH.value
})

const getBarStyle = (item) => {
  if (!timeLabels.value.length) return {}
  const totalPx = timelineWidth.value
  const startMs = timeLabels.value[0].date.getTime()
  const rangeMs = (timeLabels.value.length - 1) * msPerUnit.value
  if (rangeMs <= 0) return {}

  const leftPx = ((item.start.getTime() - startMs) / rangeMs) * totalPx
  const widthPx = ((item.end.getTime() - item.start.getTime()) / rangeMs) * totalPx
  const lane = item.lane ?? 0
  const topPx = lane * LANE_HEIGHT + 4

  return {
    left: `${Math.max(leftPx, 0)}px`,
    width: `${Math.max(widthPx, MIN_BAR_WIDTH)}px`,
    top: `${topPx}px`
  }
}

const getRowHeight = (laneCount) => Math.max(56, laneCount * LANE_HEIGHT)

const groupedByCve = computed(() => {
  void timelineWidth.value

  const totalPx = timelineWidth.value
  const startMs = timeLabels.value[0]?.date?.getTime() ?? 0
  const rangeMs = (timeLabels.value.length - 1) * msPerUnit.value

  // Deduplicate input segments by CVE + agent + status + start time
  const seen = new Set()
  const uniqueSegments = paginatedData.value.filter(seg => {
    const key = `${seg.cve_id}|${seg.agent_name || ''}|${seg.status}|${seg.start.getTime()}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })

  // Group by cve_id + agent_name
  const cveMap = new Map()
  uniqueSegments.forEach(seg => {
    const key = `${seg.cve_id}::${seg.agent_name || 'unknown'}::${seg.agent_id || ''}`
    if (!cveMap.has(key)) {
      cveMap.set(key, {
        cve_id: seg.cve_id,
        agent_name: seg.agent_name,
        agent_id: seg.agent_id,
        severity: seg.severity,
        description: seg.description,
        segments: []
      })
    }
    cveMap.get(key).segments.push(seg)
  })

  // Process each CVE+agent group
  const agentGroups = Array.from(cveMap.values())
  agentGroups.forEach(group => {
    group.segments.sort((a, b) => a.start.getTime() - b.start.getTime())

    // Compute pixel geometry
    group.segments.forEach(seg => {
      const style = getBarStyle(seg)
      seg._leftPx = parseFloat(style.left) || 0
      seg._barWidthPx = parseFloat(style.width) || MIN_BAR_WIDTH
      // Use true width (before floor) for lane overlap detection
      seg._trueRightPx = seg._leftPx + ((seg.end.getTime() - seg.start.getTime()) / rangeMs) * totalPx
      seg._rightPx = seg._leftPx + seg._barWidthPx
    })

    // Greedy lane assignment using TRUE width (not floored)
    const lanes = []
    group.segments.forEach(seg => {
      let assignedLane = -1
      for (let i = 0; i < lanes.length; i++) {
        if (seg._leftPx >= lanes[i]) {
          assignedLane = i
          break
        }
      }
      if (assignedLane === -1) {
        assignedLane = lanes.length
        lanes.push(0)
      }
      lanes[assignedLane] = seg._trueRightPx
      seg.lane = assignedLane
    })

    group.laneCount = Math.max(lanes.length, 1)
    group.key = `${group.cve_id}-${group.agent_name || 'unknown'}-${group.agent_id || ''}`
    group.first_seen = group.segments[0]?.first_seen
    group.resolved_at = group.segments.find(s => s.resolved_at)?.resolved_at
    group.reopened_at = group.segments.findLast(s => s.reopened_at)?.reopened_at
  })

  // Now group agents under their CVE, deduplicating by agent key
  const cveGroups = new Map()
  agentGroups.forEach(agent => {
    if (!cveGroups.has(agent.cve_id)) {
      cveGroups.set(agent.cve_id, {
        cve_id: agent.cve_id,
        severity: agent.severity,
        description: agent.description,
        agents: [],
        reopenCount: 0,
        _seenAgents: new Set()
      })
    }
    const cve = cveGroups.get(agent.cve_id)
    if (!cve._seenAgents.has(agent.key)) {
      cve._seenAgents.add(agent.key)
      cve.agents.push(agent)
    }
  })

  // Calculate reopenCount per CVE
  cveGroups.forEach(cve => {
    cve.reopenCount = Math.max(...cve.agents.map(a =>
      a.segments.filter(s => s.status === 'REOPENED').length
    ), 0)
    delete cve._seenAgents
  })

  return Array.from(cveGroups.values())
})

const formatDate = (d) => {
  if (!d) return '-'
  const date = toLocalDate(d)
  return date.toLocaleDateString('es-CL', { day: '2-digit', month: 'short', year: 'numeric' })
}
</script>

<style scoped>
.gantt-card {
  background: var(--surface, #ffffff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: var(--radius-lg, 8px);
  overflow: hidden;
  min-width: 0;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
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
}

.date-input {
  padding: 4px 6px;
  border: 1px solid #cbd5e1;
  border-radius: 4px;
  font-size: 11px;
  background: white;
  color: #334155;
  outline: none;
  width: 200px;
}

.date-input:focus {
  border-color: #3d6a00;
  box-shadow: 0 0 0 2px rgba(61, 106, 0, 0.15);
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

.legend-dot.pending {
  background-color: #ba1a1a;
}

.legend-dot.resolved {
  background-color: #6ca42c;
}

.legend-dot.reopened {
  background-color: #ca8a04;
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
  height: 56px;
  border-bottom: 1px solid #e2e8f0;
  flex-shrink: 0;
  align-items: flex-start;
  transition: height 0.2s ease;
  min-width: fit-content;
}

.gantt-row.agent-row:hover {
  background: #f8fafc;
}

.cve-header-row {
  display: flex;
  background: #f1f5f9;
  border-top: 2px solid #94a3b8;
  flex-shrink: 0;
  min-width: fit-content;
  height: 32px;
  align-items: center;
}

.cve-header-sidebar {
  width: 260px;
  flex-shrink: 0;
  padding: 4px 10px;
  display: flex;
  align-items: center;
  gap: 6px;
  border-right: 1px solid #e2e8f0;
}

.cve-header-chart {
  flex-shrink: 0;
}

.cve-agent-count {
  font-size: 9px;
  color: #64748b;
  font-weight: 500;
}

.agent-top {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-bottom: 2px;
}

.agent-name {
  font-family: monospace;
  font-size: 10px;
  font-weight: 600;
  color: #334155;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 200px;
}

.gantt-sidebar-cell {
  width: 260px;
  flex-shrink: 0;
  padding: 6px 10px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  border-right: 1px solid #e2e8f0;
  overflow: hidden;
}

.gantt-chart-cell {
  position: relative;
  flex-shrink: 0;
  height: 100%;
}

.gantt-bar {
  position: absolute;
  height: 20px;
  border-radius: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0;
  font-size: 9px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  z-index: 0;
}

.gantt-bar {
  position: absolute;
  top: 0;
  height: 20px;
  border-radius: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0;
  font-size: 9px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
}

.bar-label {
  opacity: 0;
  transition: opacity 0.15s ease;
}

.bar-label.visible {
  opacity: 1;
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

.reopen-badge {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  font-size: 9px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 3px;
  background: #fef3c7;
  color: #92400e;
  border: 1px solid #fbbf24;
  line-height: 1;
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

.cve-desc {
  font-size: 10px;
  color: #64748b;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 2px;
}

.cve-dates-inline {
  display: flex;
  gap: 6px;
  overflow: hidden;
}

.date-chip {
  font-size: 9px;
  padding: 1px 5px;
  border-radius: 3px;
  font-weight: 600;
  white-space: nowrap;
}

.date-chip.detected {
  background: #f1f5f9;
  color: #475569;
}

.date-chip.resolved {
  background: #dcfce7;
  color: #166534;
}

.date-chip.reopened {
  background: #fef3c7;
  color: #92400e;
}

.gantt-bar.pending {
  background-color: rgba(186, 26, 26, 0.15);
  border: 1px solid #ba1a1a;
  color: #b91c1c;
}

.gantt-bar.resolved {
  background-color: rgba(108, 164, 44, 0.15);
  border: 1px solid #6ca42c;
  color: #3f6212;
}

.gantt-bar.reopened {
  background-color: rgba(234, 179, 8, 0.15);
  border: 1px solid #ca8a04;
  color: #854d0e;
}

.bar-label {
  opacity: 0;
  transition: opacity 0.15s ease;
}

.bar-label.visible {
  opacity: 1;
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
</style>
