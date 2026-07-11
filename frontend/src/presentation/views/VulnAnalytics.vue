<template>
  <div class="fade-in">
    <div class="header-actions">
      <div>
        <h1 class="title">Analítica de Vulnerabilidades</h1>
        <p class="subtitle">Distribución de vulnerabilidades, agentes afectados y seguimiento por CVE.</p>
      </div>
    </div>

    <div v-if="errorBanner" class="status-banner status-error">{{ errorBanner }}</div>

    <div class="metrics-bar">
      <div class="mini-chart">
        <span class="mini-chart-label">Severidad</span>
        <div class="chart-group">
          <div class="mini-chart-inner">
            <Pie :data="pieChartData" :options="pieOptions" />
          </div>
          <div class="chart-inline-legend">
            <div v-for="sev in SEVERITY_ORDER" :key="sev" class="legend-item">
              <span class="legend-dot" :style="{ background: SEVERITY_COLORS[sev] }"></span>
              <span class="legend-label">{{ sev === 'CRITICAL' ? 'CRIT' : sev === 'MEDIUM' ? 'MED' : sev === 'LOW' ? 'LOW' : 'HIGH' }}</span>
              <span class="legend-value">{{ severityDistribution[sev] }}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="metric-divider"></div>
      <div class="mini-chart">
        <span class="mini-chart-label">Estado</span>
        <div class="chart-group">
          <div class="mini-chart-inner">
            <Doughnut :data="doughnutChartData" :options="doughnutOptions" />
          </div>
          <div class="chart-inline-legend">
            <div v-for="st in STATUS_ORDER" :key="st" class="legend-item">
              <span class="legend-dot" :style="{ background: STATUS_COLORS[st] }"></span>
              <span class="legend-label">{{ st === 'Reabierto' ? 'REAB' : st === 'Resuelto' ? 'RES' : 'ACT' }}</span>
              <span class="legend-value">{{ statusDistribution[st] }}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="metric-divider"></div>
      <div class="metric-group">
        <span class="metric-label">Top agente</span>
        <span class="metric-value">{{ topAgentsDistribution[0]?.agent || '—' }} ({{ topAgentsDistribution[0]?.count || 0 }})</span>
      </div>
      <div class="metric-divider"></div>
      <div class="metric-group">
        <span class="metric-label">Críticas</span>
        <span class="metric-value critical-text">{{ criticalCount }}</span>
        <span v-if="topCriticalCve" class="metric-cve">{{ topCriticalCve }}</span>
      </div>
    </div>

    <TimelineFilters
      :connections="connections"
      :agent-options="agentOpts"
      :vuln-options="vulnOpts"
      :selected-connection="selectedConnection"
      :selected-agents="selectedAgents"
      :selected-vulns="selectedVulns"
      :severity-options="severityFilterOptions"
      :selected-severities="selectedSeverities"
      :period="period"
      :periods="periods"
      :custom-date="customDate"
      :loading="loading"
      compact
      @update:selected-connection="selectedConnection = $event"
      @update:selected-agents="selectedAgents = $event"
      @update:selected-vulns="selectedVulns = $event"
      @update:selected-severities="selectedSeverities = $event"
      @update:custom-date="customDate = $event"
      @connection-change="onConnectionChange"
      @set-period="period = $event"
      @build="buildAnalytics"
    />

    <GanttTab v-if="!loading" :gantt-data="ganttData" />

    <div v-else class="card loading-card">
      <div class="loading-progress">
        <div class="loading-info">
          <p class="loading-message">{{ loadingMessage || 'Cargando...' }}</p>
          <p v-if="!fetchProgress.done && fetchProgress.current > 0" class="loading-detail">
            Página {{ fetchProgress.current }}
          </p>
          <p v-if="fetchProgress.done" class="loading-detail loading-done">
            {{ fetchProgress.current }} páginas cargadas
          </p>
          <p v-if="elapsedSeconds >= 3" class="loading-detail">
            {{ elapsedSeconds }}s transcurridos
          </p>
        </div>
      </div>
      <div class="loading-bar-track">
        <div class="loading-bar-fill" :style="{ width: loadingBarWidth + '%' }"></div>
      </div>
      <button v-if="!fetchProgress.done" class="btn btn-cancel" @click="cancelBuild">Cancelar</button>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useVulnStore } from '../../application/stores/vulnStore'
import wazuhService from '../../application/services/wazuhService'
import { Pie, Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip
} from 'chart.js'

ChartJS.register(ArcElement, Tooltip)

import TimelineFilters from './timeline/components/TimelineFilters.vue'
import GanttTab from './timeline/components/GanttTab.vue'

const store = useVulnStore()

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
  { l: 'Dia', v: 'day' },
  { l: 'Todo', v: 'all' }
]

// ── Filter state ──
const connections = ref([])
const selectedConnection = ref('')
const agentOpts = ref([])
const vulnOpts = ref([])
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedSeverities = ref(['CRITICAL', 'HIGH'])
const period = ref('30d')
const customDate = ref(new Date().toISOString().split('T')[0])
const errorBanner = ref('')

// ── Data state ──
const filteredVulnsData = ref([])
const hasBuilt = ref(false)

// ── Severity-filtered view ──
const filteredData = computed(() => {
  if (!hasBuilt.value || filteredVulnsData.value.length === 0) return filteredVulnsData.value
  if (selectedSeverities.value.length === 0) return filteredVulnsData.value
  return filteredVulnsData.value.filter(v => {
    const sev = (v.severity || 'LOW').toUpperCase()
    return selectedSeverities.value.includes(sev)
  })
})

const toggleSeverity = (sev) => {
  if (selectedSeverities.value.includes(sev)) {
    selectedSeverities.value = selectedSeverities.value.filter(s => s !== sev)
  } else {
    selectedSeverities.value = [...selectedSeverities.value, sev]
  }
}

// ── Loading state ──
const loading = ref(false)
const loadingMessage = ref('')
const elapsedSeconds = ref(0)
const fetchProgress = ref({ current: 0 })
let timerInterval = null

// ── Computed chart data ──

const severityDistribution = computed(() => {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  filteredData.value.forEach(v => {
    const sev = (v.severity || 'LOW').toUpperCase()
    if (counts[sev] !== undefined) counts[sev]++
  })
  return counts
})

const statusDistribution = computed(() => {
  const counts = { Activo: 0, Resuelto: 0, Reabierto: 0 }
  filteredData.value.forEach(v => {
    const mapped = v.status ? STATUS_API_MAP[v.status] : null
    if (mapped && counts[mapped] !== undefined) counts[mapped]++
  })
  return counts
})

const topAgentsDistribution = computed(() => {
  const agentMap = {}
  filteredData.value.forEach(v => {
    const agent = v.agent_name || 'unknown'
    agentMap[agent] = (agentMap[agent] || 0) + 1
  })
  return Object.entries(agentMap)
    .map(([agent, count]) => ({ agent, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
})

const criticalCount = computed(() => {
  return filteredData.value.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL').length
})

const topCriticalCve = computed(() => {
  const criticalVulns = filteredVulnsData.value.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL')
  if (criticalVulns.length === 0) return null
  const cveCounts = {}
  criticalVulns.forEach(v => {
    if (v.cve_id) cveCounts[v.cve_id] = (cveCounts[v.cve_id] || 0) + 1
  })
  const sorted = Object.entries(cveCounts).sort((a, b) => b[1] - a[1])
  return sorted.length > 0 ? sorted[0][0] : null
})

// ── Inline chart data ──

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const SEVERITY_COLORS = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#eab308', LOW: '#22c55e' }
const STATUS_COLORS = { Activo: '#dc2626', Resuelto: '#6ca42c', Reabierto: '#ca8a04' }
const STATUS_ORDER = ['Activo', 'Resuelto', 'Reabierto']
const STATUS_API_MAP = { Detected: 'Activo', Resolved: 'Resuelto', 'Re-emerged': 'Reabierto' }

const SEVERITY_SHORT_LABEL = { CRITICAL: 'CRIT', HIGH: 'HIGH', MEDIUM: 'MED', LOW: 'LOW' }
const severityFilterOptions = SEVERITY_ORDER.map(sev => ({
  value: sev,
  label: SEVERITY_SHORT_LABEL[sev]
}))

const pieChartData = computed(() => ({
  labels: SEVERITY_ORDER,
  datasets: [{
    data: SEVERITY_ORDER.map(sev => severityDistribution.value[sev] ?? 0),
    backgroundColor: SEVERITY_ORDER.map(sev => SEVERITY_COLORS[sev]),
    borderWidth: 1,
    borderColor: '#ffffff'
  }]
}))

const doughnutChartData = computed(() => ({
  labels: STATUS_ORDER,
  datasets: [{
    data: STATUS_ORDER.map(st => statusDistribution.value[st] ?? 0),
    backgroundColor: STATUS_ORDER.map(st => STATUS_COLORS[st]),
    borderWidth: 1,
    borderColor: '#ffffff'
  }]
}))

const pieOptions = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: { display: false },
    tooltip: {
      enabled: false
    }
  }
}

const doughnutOptions = {
  ...pieOptions,
  cutout: '55%'
}

const ganttData = computed(() => {
  return hasBuilt.value && filteredData.value.length > 0 ? filteredData.value : []
})

const loadingBarWidth = computed(() => {
  if (fetchProgress.value.done) return 100
  return Math.min(fetchProgress.value.current * 20, 80)
})

// ── Timer helpers ──

const startTimer = () => {
  elapsedSeconds.value = 0
  clearInterval(timerInterval)
  timerInterval = setInterval(() => { elapsedSeconds.value++ }, 1000)
}

const stopTimer = () => {
  clearInterval(timerInterval)
  timerInterval = null
}

const cancelBuild = () => {
  stopTimer()
  loading.value = false
  loadingMessage.value = 'Operación cancelada'
  fetchProgress.value = { current: 0 }
  store.clearConnectionData()
}

// ── Build flow ──

const onConnectionChange = async () => {
  selectedAgents.value = []
  selectedVulns.value = []
  agentOpts.value = []
  vulnOpts.value = []
  errorBanner.value = ''

  if (selectedConnection.value) {
    try {
      const filterOptions = await store.fetchFilterOptions(selectedConnection.value)
      agentOpts.value = filterOptions.agents || []
      vulnOpts.value = filterOptions.cves || []
    } catch (error) {
      console.error(error)
      errorBanner.value = 'No se pudieron cargar agentes y CVEs para la conexión seleccionada.'
    }
  }

  // Reload data when connection changes
  await buildAnalytics()
}

const buildAnalytics = async () => {
  errorBanner.value = ''
  hasBuilt.value = false
  loading.value = true
  loadingMessage.value = 'Obteniendo datos...'
  fetchProgress.value = { current: 0 }
  startTimer()

  try {
    // Fetch all vulns (without connectionId when none selected → returns ALL)
    const connId = selectedConnection.value || undefined
    const allVulns = await store.fetchAllVulns(connId)
    fetchProgress.value = { current: 1, done: true }

    // Apply period filter client-side
    let result = store.filterByPeriod(allVulns, period.value, customDate.value)

    // Apply agent and CVE filters
    if (selectedAgents.value.length > 0) {
      result = result.filter(v => selectedAgents.value.includes(v.agent_name))
    }
    if (selectedVulns.value.length > 0) {
      result = result.filter(v => selectedVulns.value.includes(v.cve_id))
    }

    loadingMessage.value = 'Procesando datos...'
    filteredVulnsData.value = result
    hasBuilt.value = true
  } catch (err) {
    console.error('Error fetching vulns:', err)
    errorBanner.value = 'Error al cargar vulnerabilidades. Verifica tu conexión Wazuh.'
    hasBuilt.value = false
  } finally {
    stopTimer()
    loading.value = false
  }
}

// ── Lifecycle ──

onMounted(async () => {
  try {
    const response = await wazuhService.getConnections()
    connections.value = Array.isArray(response.data) ? response.data : []
    // Auto-select first connection if available
    if (connections.value.length > 0) {
      selectedConnection.value = connections.value[0].id
    }
    // Auto-load analytics data
    await buildAnalytics()
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar las conexiones Wazuh.'
  }
})

onUnmounted(() => {
  stopTimer()
})
</script>

<style scoped>
.header-actions {
  margin-bottom: 1.5rem;
}

.status-banner {
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--border);
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.status-error {
  color: var(--danger);
  background: var(--danger-bg);
  border-color: rgba(220, 38, 38, 0.3);
}

/* ── Metrics Bar ── */
.metrics-bar {
  display: flex;
  align-items: center;
  justify-content: space-evenly;
  gap: 0.5rem;
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: var(--radius-md, 6px);
  padding: 0.6rem 1rem;
  margin-bottom: 0.75rem;
}

.mini-chart {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-shrink: 0;
}

.mini-chart-label {
  font-size: 0.6rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted, #64748b);
  letter-spacing: 0.05em;
  writing-mode: vertical-lr;
  text-orientation: mixed;
}

/* Chart ra + inline legend next to it */
.chart-group {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.mini-chart-inner {
  width: 72px;
  height: 72px;
}

.chart-inline-legend {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.2rem;
  white-space: nowrap;
}

.legend-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  flex-shrink: 0;
}

.legend-label {
  font-size: 0.5rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted, #64748b);
  letter-spacing: 0.03em;
  line-height: 1.1;
}

.legend-value {
  font-size: 0.65rem;
  font-weight: 700;
  color: var(--text, #1e293b);
  line-height: 1.1;
}

.metric-group {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.2rem;
  flex-shrink: 0;
}

.metric-label {
  font-size: 0.6rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted, #64748b);
  letter-spacing: 0.05em;
}

.metric-value {
  font-weight: 700;
  font-size: 1rem;
  color: var(--text, #1e293b);
}

.metric-cve {
  font-family: monospace;
  font-size: 0.7rem;
  color: var(--text-muted, #64748b);
}

.metric-divider {
  width: 1px;
  height: 3rem;
  background: var(--border, #e2e8f0);
  flex-shrink: 0;
}

.critical-text {
  color: #dc2626;
}

@media (max-width: 900px) {
  .metrics-bar {
    flex-wrap: wrap;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.5rem;
  }
  .metric-divider {
    display: none;
  }
  .mini-chart-inner {
    width: 62px;
    height: 62px;
  }
  .legend-label {
    font-size: 0.45rem;
  }
  .legend-value {
    font-size: 0.6rem;
  }
}

/* ── Loading card (same pattern as Timeline) ── */
.loading-card {
  min-height: 200px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 1rem;
  padding: 2rem;
}

.loading-progress {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.loading-info {
  text-align: left;
}

.loading-message {
  font-weight: 600;
  font-size: 1rem;
  color: var(--text, #1e293b);
  margin: 0;
}

.loading-detail {
  font-size: 0.8rem;
  color: var(--text-muted, #64748b);
  margin: 0.2rem 0 0 0;
}

.loading-bar-track {
  width: 100%;
  max-width: 400px;
  height: 6px;
  background: var(--border, #e2e8f0);
  border-radius: 3px;
  overflow: hidden;
}

.loading-bar-fill {
  height: 100%;
  background: var(--primary, #3d6a00);
  border-radius: 3px;
  transition: width 0.3s ease;
  width: 100%;
}

.loading-done {
  color: var(--primary, #3d6a00);
  font-weight: 600;
}

.btn-cancel {
  padding: 0.4rem 1rem;
  font-size: 0.8rem;
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 4px;
  background: white;
  color: var(--text-muted, #64748b);
  cursor: pointer;
  transition: all 0.2s;
}

.btn-cancel:hover {
  background: #fef2f2;
  border-color: #f87171;
  color: #b91c1c;
}
</style>
