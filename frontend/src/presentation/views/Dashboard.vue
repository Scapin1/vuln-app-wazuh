<template>
  <div class="fade-in">
    <!-- Header Area -->
    <div class="header-actions">
      <div>
        <h1 class="title">Panorama de Amenazas</h1>
        <p class="subtitle">Visualiza y gestiona el inventario de vulnerabilidades reportado por Wazuh.</p>
      </div>
      <div>
        <button class="btn btn-primary" @click="syncVulns" :disabled="syncing">
          <svg v-if="syncing" class="spin" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-9.5l1.75 1.93"></path></svg>
          {{ syncing ? 'Sincronizando con Wazuh...' : 'Forzar Sincronización' }}
        </button>
      </div>
    </div>

    <!-- Error/Loading states -->
    <div v-if="error" class="alert alert-danger fade-in">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      {{ error }}
    </div>

    <!-- Charts Row -->
    <div v-if="!loading && vulns.length > 0" class="charts-row">
      <div class="chart-col">
        <SeverityChart :data="severityDistribution" />
      </div>
      <div class="chart-col">
        <StatusChart :data="statusDistribution" />
      </div>
    </div>

    <!-- Filter Toggle Bar (minimalista) -->
    <div v-if="!loading && vulns.length > 0" class="filter-toggle-bar">
      <button class="btn-filter-toggle" @click="showFilters = !showFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
        </svg>
        <span>{{ showFilters ? 'Ocultar filtros' : 'Filtros avanzados' }}</span>
      </button>
      <button v-if="showFilters" class="btn-clear-filters" @click="clearFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 6h18"></path>
          <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
          <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
        </svg>
        <span>Limpiar</span>
      </button>
    </div>

    <!-- Dashboard Filters -->
    <div v-show="showFilters" class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label>Conexión Wazuh</label>
          <select v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="">Todas las conexiones</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.agents = false)">
          <label>Agentes</label>
          <button class="filter-input dd-btn" @click="dropdowns.agents = !dropdowns.agents" :disabled="!agentOptions.length">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.agents" class="dd-panel fade-in">
            <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedAgents = [...agentOptions]">Todos</span>
              <span @click="selectedAgents = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="agent in filteredAgents" :key="agent" class="dd-item">
                <input type="checkbox" :value="agent" v-model="selectedAgents"> {{ agent }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.vulns = false)">
          <label>CVE ID</label>
          <button class="filter-input dd-btn" @click="dropdowns.vulns = !dropdowns.vulns" :disabled="!vulnOptions.length">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.vulns" class="dd-panel fade-in">
            <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedVulns = [...vulnOptions]">Todas</span>
              <span @click="selectedVulns = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="vuln in filteredCVEOptions" :key="vuln" class="dd-item">
                <input type="checkbox" :value="vuln" v-model="selectedVulns"> {{ vuln }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.packages = false)">
          <label>Software Afectado</label>
          <button class="filter-input dd-btn" @click="dropdowns.packages = !dropdowns.packages" :disabled="!packageOptions.length">
            <span>{{ selectedPackages.length ? selectedPackages.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.packages" class="dd-panel fade-in">
            <input type="text" v-model="search.package" placeholder="Buscar software..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedPackages = [...packageOptions]">Todos</span>
              <span @click="selectedPackages = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="pkg in filteredPackages" :key="pkg" class="dd-item">
                <input type="checkbox" :value="pkg" v-model="selectedPackages"> {{ pkg }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.severity = false)">
          <label>Severidad</label>
          <button class="filter-input dd-btn" @click="dropdowns.severity = !dropdowns.severity" :disabled="!severityOptions.length">
            <span>{{ selectedSeverities.length ? selectedSeverities.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.severity" class="dd-panel fade-in">
            <div class="dd-actions">
              <span @click="selectedSeverities = [...severityOptions]">Todas</span>
              <span @click="selectedSeverities = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="sev in severityOptions" :key="sev" class="dd-item">
                <input type="checkbox" :value="sev" v-model="selectedSeverities"> 
                <span :class="'badge-mini ' + getSeverityBadgeClass(sev)">{{ sev }}</span>
              </label>
            </div>
          </div>
        </div>

        <div class="f-group">
          <label>Score CVSS (Base)</label>
          <div class="range-inputs">
            <input type="number" v-model.number="scoreMin" min="0" max="10" step="0.1" placeholder="Min" class="filter-input-sm">
            <span>-</span>
            <input type="number" v-model.number="scoreMax" min="0" max="10" step="0.1" placeholder="Max" class="filter-input-sm">
          </div>
        </div>
      </div>
    </div>

    <!-- Loading card with progress (same design as Timeline) -->
    <div v-if="loading" class="card loading-card">
      <div class="loading-progress">
        <div class="loading-info">
          <p class="loading-message">{{ loadingMessage || 'Cargando...' }}</p>
          <p v-if="fetchProgress.current > 0" class="loading-detail">
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

    <!-- Table (VulnTable component) -->
    <VulnTable v-if="!loading" :vulns="filteredVulns" :loading="loading" />
  </div>
</template>

<script setup>
import { ref, onMounted, computed, watch, reactive, onUnmounted } from 'vue'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'
import SeverityChart from './dashboard/components/SeverityChart.vue'
import StatusChart from './dashboard/components/StatusChart.vue'
import VulnTable from './timeline/components/VulnTable.vue'

const vulns = ref([])
const loading = ref(true)
const syncing = ref(false)
const error = ref('')
const showFilters = ref(false)

// Loading progress (same pattern as timeline)
const loadingMessage = ref('')
const elapsedSeconds = ref(0)
const fetchProgress = ref({ current: 0 })
let abortController = null
let timerInterval = null

const TICK_INTERVAL_MS = 1000
const PAGE_SIZE = 10000

const startTimer = () => {
  elapsedSeconds.value = 0
  clearInterval(timerInterval)
  timerInterval = setInterval(() => { elapsedSeconds.value++ }, TICK_INTERVAL_MS)
}

const stopTimer = () => {
  clearInterval(timerInterval)
  timerInterval = null
}

const cancelBuild = () => {
  if (abortController) {
    abortController.abort()
    abortController = null
  }
  stopTimer()
  loading.value = false
  loadingMessage.value = 'Operación cancelada'
  fetchProgress.value = { current: 0 }
}

const loadingBarWidth = computed(() => {
  if (fetchProgress.value.done) return 100
  return Math.min(fetchProgress.value.current * 20, 80)
})

// Filter state
const connections = ref([])
const agentOptions = ref([])
const vulnOptions = ref([])
const packageOptions = ref([])
const severityOptions = ref([])

const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedPackages = ref([])
const selectedSeverities = ref([])
const scoreMin = ref('')
const scoreMax = ref('')

// Dropdown state
const search = reactive({ agent: '', vuln: '', package: '' })
const dropdowns = reactive({ agents: false, vulns: false, packages: false, severity: false })

// Filtered lists for search
const filteredAgents = computed(() =>
  agentOptions.value.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredCVEOptions = computed(() =>
  vulnOptions.value.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)

const filteredPackages = computed(() =>
  packageOptions.value.filter(pkg => pkg.toLowerCase().includes(search.package.toLowerCase()))
)

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1 // low or unknown
}

const updateFilterOptions = () => {
  const agents = new Set()
  const vulnIds = new Set()
  const packages = new Set()
  const severities = new Set()

  vulns.value.forEach(vuln => {
    if (vuln.agent_name) agents.add(vuln.agent_name)
    if (vuln.cve_id) vulnIds.add(vuln.cve_id)
    if (vuln.package_name) packages.add(vuln.package_name)
    if (vuln.severity) severities.add(vuln.severity.toUpperCase())
  })

  agentOptions.value = Array.from(agents).sort()
  vulnOptions.value = Array.from(vulnIds).sort()
  packageOptions.value = Array.from(packages).sort()
  severityOptions.value = Array.from(severities).sort((a, b) => {
    const levelA = getSeverityLevel(a.toLowerCase())
    const levelB = getSeverityLevel(b.toLowerCase())
    return levelB - levelA
  })
}

const matchesConnection = (vuln) => 
  !selectedConnection.value || vuln.connection_id === selectedConnection.value

const matchesAgent = (vuln) => 
  selectedAgents.value.length === 0 || selectedAgents.value.includes(vuln.agent_name)

const matchesVuln = (vuln) => 
  selectedVulns.value.length === 0 || selectedVulns.value.includes(vuln.cve_id)

const matchesPackage = (vuln) => 
  selectedPackages.value.length === 0 || selectedPackages.value.includes(vuln.package_name)

const matchesSeverity = (vuln) => {
  if (selectedSeverities.value.length === 0) return true
  const vulnSeverity = (vuln.severity || 'UNKNOWN').toUpperCase()
  return selectedSeverities.value.includes(vulnSeverity)
}

const matchesScore = (vuln) => {
  if (scoreMin.value === '' && scoreMax.value === '') return true
  
  const score = vuln.score_base
  if (score === null || score === undefined) return false
  
  const minOk = scoreMin.value === '' || score >= scoreMin.value
  const maxOk = scoreMax.value === '' || score <= scoreMax.value
  
  return minOk && maxOk
}

const filteredVulns = computed(() => {
  return vulns.value.filter(vuln => {
    return matchesConnection(vuln) &&
           matchesAgent(vuln) &&
           matchesVuln(vuln) &&
           matchesPackage(vuln) &&
           matchesSeverity(vuln) &&
           matchesScore(vuln)
  })
})

const severityDistribution = computed(() => {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  filteredVulns.value.forEach(v => {
    const sev = (v.severity || 'LOW').toUpperCase()
    if (counts[sev] !== undefined) counts[sev]++
  })
  return counts
})

const statusDistribution = computed(() => {
  const counts = { Detected: 0, Resolved: 0, 'Re-emerged': 0 }
  vulns.value.forEach(v => {
    if (v.status && counts[v.status] !== undefined) counts[v.status]++
  })
  return counts
})

const onConnectionChange = () => {
  // When connection changes, clear dependent filters
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  scoreMin.value = ''
  scoreMax.value = ''
}

const clearFilters = () => {
  selectedConnection.value = ''
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  scoreMin.value = ''
  scoreMax.value = ''
}

const fetchVulns = async () => {
  loading.value = true
  error.value = ''
  loadingMessage.value = ''
  fetchProgress.value = { current: 0 }
  startTimer()

  abortController = new AbortController()
  const signal = abortController.signal

  try {
    let allData = []
    let offset = 0
    let pageNum = 0
    while (true) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')

      const res = await vulnService.getVulns({ limit: PAGE_SIZE, offset }, { signal })
      const data = Array.isArray(res.data) ? res.data : []
      allData = allData.concat(data)
      pageNum++

      fetchProgress.value = { current: pageNum }
      loadingMessage.value = 'Obteniendo datos...'

      if (data.length < PAGE_SIZE) break
      offset += PAGE_SIZE
    }

    fetchProgress.value = { current: pageNum, done: true }
    loadingMessage.value = `Cargando gráficos...`

    if (allData.length > 0) {
      vulns.value = allData
      updateFilterOptions()
    } else {
      vulns.value = []
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      loadingMessage.value = 'Operación cancelada'
      return
    }
    console.error('Error fetching vulns:', err)
    error.value = 'Error al cargar vulnerabilidades. Verifica tu conexión Wazuh.'
  } finally {
    stopTimer()
    loading.value = false
    abortController = null
  }
}

const fetchConnections = async () => {
  try {
    const res = await wazuhService.getConnections()
    connections.value = res?.data || []
  } catch (err) {
    console.error('Error fetching connections:', err)
    connections.value = []
  }
}

const syncVulns = async () => {
  syncing.value = true
  error.value = ''
  try {
    await vulnService.syncVulns()
    await fetchVulns()
  } catch (err) {
    error.value = 'Error durante la sincronización con Wazuh. Verifica tu configuración en Admin Wazuh.'
  } finally {
    syncing.value = false
  }
}

const getSeverityBadgeClass = (severity) => {
  const s = severity.toLowerCase()
  if (['critical', 'critica'].includes(s)) return 'badge-critical'
  if (['high', 'alta'].includes(s)) return 'badge-high'
  if (['medium', 'media'].includes(s)) return 'badge-medium'
  return 'badge-low'
}

onMounted(() => {
  fetchConnections()
  fetchVulns()
})

onUnmounted(() => {
  stopTimer()
})
</script>

<style scoped>
.header-actions {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.alert {
  padding: 1rem;
  border-radius: var(--radius-sm);
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
}
.alert-danger {
  color: var(--danger);
  background-color: var(--danger-bg);
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.filter-toggle-bar {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 0;
  margin-bottom: 0.5rem;
}

.btn-filter-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.85rem;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}

.btn-filter-toggle:hover {
  background-color: var(--bg-hover);
  border-color: var(--text-muted);
  color: var(--text-main);
}

.btn-filter-toggle svg {
  width: 16px;
  height: 16px;
}

.btn-clear-filters {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.85rem;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}

.btn-clear-filters:hover {
  background-color: var(--bg-hover);
  border-color: var(--danger);
  color: var(--danger);
}

.btn-clear-filters svg {
  width: 16px;
  height: 16px;
}

/* CHARTS ROW */
.charts-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.25rem;
  margin-bottom: 1.25rem;
}

.chart-col {
  min-width: 0;
}

@media (max-width: 768px) {
  .charts-row {
    grid-template-columns: 1fr;
  }
}

/* FILTER PANEL STYLES */
.filter-panel { 
  padding: 0; 
  margin-bottom: 1.5rem; 
  overflow: visible; 
}

.filter-row { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); 
  align-items: center; 
}

.f-group { 
  display: flex; 
  flex-direction: column; 
  padding: 1rem 1.2rem; 
  border-right: 1px solid var(--border); 
}

.f-group:last-child { 
  border-right: none; 
}

.f-group label { 
  font-size: 0.7rem; 
  font-weight: 700; 
  color: var(--text-muted); 
  text-transform: uppercase; 
  margin-bottom: 0.5rem; 
}

.filter-input, .dd-btn { 
  width: 100%; 
  padding: 0.55rem 0.8rem; 
  border: 1px solid var(--border); 
  background: var(--bg-dark); 
  border-radius: var(--radius-sm); 
  color: var(--text-main); 
  cursor: pointer; 
  font-size: 0.85rem;
}

.filter-input:disabled, .dd-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.filter-input-sm {
  width: 100%;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--border);
  background: var(--bg-dark);
  border-radius: var(--radius-sm);
  color: var(--text-main);
  font-size: 0.8rem;
}

.range-inputs {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.range-inputs span {
  color: var(--text-muted);
  font-weight: 600;
}

.popover-wrap { 
  position: relative; 
}

.dd-btn { 
  display: flex; 
  justify-content: space-between; 
}

.dd-panel { 
  position: absolute; 
  top: calc(100% + 6px); 
  left: 0; 
  width: 280px; 
  border: 1px solid var(--border); 
  border-radius: var(--radius-md); 
  background: var(--bg-panel); 
  z-index: 20; 
  overflow: hidden; 
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.dd-search { 
  width: 100%; 
  border: none; 
  border-bottom: 1px solid var(--border); 
  padding: 0.65rem 0.9rem; 
  background: var(--bg-hover); 
  color: var(--text-main); 
}

.dd-actions { 
  display: flex; 
  justify-content: space-between; 
  padding: 0.5rem 0.9rem; 
  border-bottom: 1px solid var(--border); 
  font-size: 0.75rem; 
  color: var(--primary); 
}

.dd-actions span { 
  cursor: pointer; 
}

.dd-actions span:hover {
  text-decoration: underline;
}

.dd-list { 
  max-height: 220px; 
  overflow-y: auto; 
}

.dd-item { 
  display: flex; 
  gap: 0.6rem; 
  padding: 0.5rem 0.9rem; 
  font-size: 0.82rem; 
  cursor: pointer;
  align-items: center;
}

.dd-item:hover {
  background: var(--bg-hover);
}

.badge-mini {
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
}

.badge-critical {
  background: rgba(220, 38, 38, 0.15);
  color: #dc2626;
}

.badge-high {
  background: rgba(234, 88, 12, 0.15);
  color: #ea580c;
}

.badge-medium {
  background: rgba(234, 179, 8, 0.15);
  color: #eab308;
}

.badge-low {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

/* ── Loading card (same design as Timeline) ── */
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

.loading-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid var(--border, #e2e8f0);
  border-top-color: var(--primary, #3d6a00);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  flex-shrink: 0;
}

@keyframes spin {
  to { transform: rotate(360deg); }
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

.loading-done {
  color: var(--primary, #3d6a00);
  font-weight: 600;
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
  color: #dc2626;
}

@media (max-width: 1400px) {
  .filter-row { 
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); 
  }
}

@media (max-width: 1100px) {
  .filter-row { 
    grid-template-columns: 1fr 1fr; 
  }
  .f-group { 
    border-right: none; 
    border-bottom: 1px solid var(--border); 
  }
}
</style>
