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

    <!-- Pie Charts Row (always visible when we have data) -->
    <div v-if="hasBuilt && store.dashboardVulns.length > 0" class="charts-row">
      <div class="chart-col">
        <SeverityChart :data="severityDistribution" />
      </div>
      <div class="chart-col">
        <StatusChart :data="statusDistribution" />
      </div>
    </div>

    <!-- Filter Panel -->
    <div class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label for="dashboard-connection">Conexión Wazuh</label>
          <select id="dashboard-connection" v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="" disabled>Selecciona servidor...</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
          <span class="f-group-label">Equipos / Agentes</span>
          <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'agents' ? '' : 'agents'" :disabled="!agentOptions.length">
            <span :class="selectedAgents.length ? 'sel-badge' : ''">{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="activeDropdown === 'agents'" class="dd-panel fade-in">
            <input type="text" id="dashboard-search-agent" v-model="search.agent" placeholder="Buscar agente..." class="dd-search" aria-label="Buscar agente">
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

        <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
          <span class="f-group-label">CVE ID</span>
          <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'vulns' ? '' : 'vulns'" :disabled="!vulnOptions.length">
            <span :class="selectedVulns.length ? 'sel-badge' : ''">{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="activeDropdown === 'vulns'" class="dd-panel fade-in">
            <input type="text" id="dashboard-search-vuln" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search" aria-label="Buscar CVE">
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

        <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
          <span class="f-group-label">Severidad</span>
          <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'severity' ? '' : 'severity'" :disabled="!severityOptions.length">
            <span :class="selectedSeverities.length ? 'sel-badge' : ''">{{ selectedSeverities.length ? selectedSeverities.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="activeDropdown === 'severity'" class="dd-panel fade-in">
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
          <span class="f-group-label">Periodo</span>
          <div class="chip-row">
            <button
              v-for="p in periods"
              :key="p.v"
              class="chip"
              :class="{ on: period === p.v }"
              @click="period = p.v"
            >
              {{ p.l }}
            </button>
          </div>
        </div>

        <div class="f-group" v-if="period === 'day'">
          <label for="dashboard-date">Dia</label>
          <input id="dashboard-date" type="date" v-model="customDate" class="filter-input">
        </div>

        <div class="f-group f-action">
          <button class="btn btn-primary" @click="buildDashboard" :disabled="!selectedConnection || loading">
            {{ loading ? 'Analizando...' : 'Generar Vista' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Loading card -->
    <div v-if="loading" class="card loading-card">
      <div class="loading-progress">
        <div class="loading-info">
          <p class="loading-message">{{ loadingMessage || 'Cargando...' }}</p>
          <p class="loading-detail">Obteniendo datos de vulnerabilidades...</p>
        </div>
      </div>
      <div class="loading-bar-track">
        <div class="loading-bar-fill loading-bar-ani"></div>
      </div>
    </div>

    <!-- Empty / Not built yet -->
    <div v-else-if="!hasBuilt" class="card empty-card">
      <h3>Sistema de Seguimiento de Vulnerabilidades</h3>
      <p>Selecciona una conexión Wazuh y presiona "Generar Vista" para visualizar las vulnerabilidades.</p>
    </div>

    <!-- Content: GanttTab + VulnTable -->
    <template v-else-if="hasBuilt">
      <div v-if="store.dashboardVulns.length === 0" class="card empty-card">
        <h3>Sin datos para mostrar</h3>
        <p>No se encontraron vulnerabilidades para los filtros seleccionados.</p>
      </div>
      <template v-else>
        <GanttTab :gantt-data="filteredVulns" />
        <VulnTable :vulns="filteredVulns" :loading="false" />
      </template>
    </template>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, reactive } from 'vue'
import { useVulnStore } from '../../application/stores/vulnStore'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'
import SeverityChart from './dashboard/components/SeverityChart.vue'
import StatusChart from './dashboard/components/StatusChart.vue'
import VulnTable from './timeline/components/VulnTable.vue'
import GanttTab from './timeline/components/GanttTab.vue'

const store = useVulnStore()

// State
const syncing = ref(false)
const error = ref('')
const hasBuilt = ref(false)

// Loading from store
const loading = computed(() => store.loading)
const loadingMessage = computed(() => store.loading ? 'Cargando datos...' : '')

// Connections
const connections = ref([])

// Filter state
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedSeverities = ref([])
const period = ref('30d')
const customDate = ref(new Date().toISOString().split('T')[0])

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
  { l: 'Dia', v: 'day' },
  { l: 'Todo', v: 'all' }
]

// Filter options (populated from store)
const agentOptions = ref([])
const vulnOptions = ref([])
const severityOptions = ref([])

// Dropdown state
const search = reactive({ agent: '', vuln: '' })
const activeDropdown = ref('')

// Filtered lists for search
const filteredAgents = computed(() =>
  agentOptions.value.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredCVEOptions = computed(() =>
  vulnOptions.value.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1
}

// Chart distributions from store
const severityDistribution = computed(() => {
  return store.dashboardVulns.length
    ? store.dashboardVulns.reduce((acc, v) => {
        const sev = (v.severity || 'LOW').toUpperCase()
        if (acc[sev] !== undefined) acc[sev]++
        return acc
      }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 })
    : { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
})

const statusDistribution = computed(() => {
  return store.dashboardVulns.length
    ? store.dashboardVulns.reduce((acc, v) => {
        if (v.status && acc[v.status] !== undefined) acc[v.status]++
        return acc
      }, { Detected: 0, Resolved: 0, 'Re-emerged': 0 })
    : { Detected: 0, Resolved: 0, 'Re-emerged': 0 }
})

// Client-side filtering on cached vulns
const filteredVulns = computed(() => {
  return (store.dashboardVulns || []).filter(vuln => {
    const byAgent = selectedAgents.value.length === 0 || selectedAgents.value.includes(vuln.agent_name)
    const byVuln = selectedVulns.value.length === 0 || selectedVulns.value.includes(vuln.cve_id)
    const bySeverity = selectedSeverities.value.length === 0 || selectedSeverities.value.includes((vuln.severity || 'UNKNOWN').toUpperCase())
    return byAgent && byVuln && bySeverity
  })
})

// Build function (called on "Generar Vista" click)
const buildDashboard = async () => {
  if (!selectedConnection.value) return

  error.value = ''
  hasBuilt.value = false
  store.invalidateCache()

  try {
    const result = await store.fetchDashboard(selectedConnection.value, period.value, customDate.value)

    if (result && result.vulns) {
      hasBuilt.value = true
      // Extract filter options from cached vulns
      const agents = new Set()
      const vulnIds = new Set()
      const severities = new Set()

      store.dashboardVulns.forEach(vuln => {
        if (vuln.agent_name) agents.add(vuln.agent_name)
        if (vuln.cve_id) vulnIds.add(vuln.cve_id)
        if (vuln.severity) severities.add(vuln.severity.toUpperCase())
      })

      agentOptions.value = Array.from(agents).sort()
      vulnOptions.value = Array.from(vulnIds).sort()
      severityOptions.value = Array.from(severities).sort((a, b) => {
        return getSeverityLevel(b) - getSeverityLevel(a)
      })

      if (!store.dashboardVulns.length) {
        error.value = 'No se encontraron vulnerabilidades para esta conexión.'
      }
    }
  } catch (err) {
    console.error('Error building dashboard:', err)
    error.value = 'Error al cargar vulnerabilidades. Verifica tu conexión Wazuh.'
  }
}

const getSeverityBadgeClass = (severity) => {
  const s = severity.toLowerCase()
  if (['critical', 'critica'].includes(s)) return 'badge-critical'
  if (['high', 'alta'].includes(s)) return 'badge-high'
  if (['medium', 'media'].includes(s)) return 'badge-medium'
  return 'badge-low'
}

const onConnectionChange = () => {
  selectedAgents.value = []
  selectedVulns.value = []
  selectedSeverities.value = []
  agentOptions.value = []
  vulnOptions.value = []
  severityOptions.value = []
  store.clearConnectionData()
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
    if (selectedConnection.value) {
      await buildDashboard()
    }
  } catch (err) {
    error.value = 'Error durante la sincronización con Wazuh. Verifica tu configuración en Admin Wazuh.'
  } finally {
    syncing.value = false
  }
}

onMounted(() => {
  fetchConnections()
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

/* EMPTY CARD */
.empty-card {
  min-height: 240px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  gap: 0.5rem;
}

.empty-card h3 {
  margin: 0;
  color: var(--text-main);
  font-weight: 600;
}

.empty-card p {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin: 0;
}

/* CHARTS ROW */
.charts-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
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

.f-group label, .f-group .f-group-label {
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 0.5rem;
}

.f-action {
  justify-content: end;
  background: var(--bg-hover);
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

.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.chip {
  padding: 0.4rem 0.8rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-dark);
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--text-muted);
  cursor: pointer;
}

.chip.on {
  background: var(--primary);
  border-color: var(--primary);
  color: #fff;
}

.sel-badge {
  background: var(--primary-bg);
  color: var(--primary);
  border-radius: 999px;
  padding: 0.1rem 0.45rem;
  font-size: 0.72rem;
  font-weight: 700;
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

/* ── Loading card ── */
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
  color: var(--text-muted, #475569);
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
  width: 100%;
}

.loading-bar-ani {
  animation: loadingPulse 1.5s ease-in-out infinite;
}

@keyframes loadingPulse {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 1; }
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
