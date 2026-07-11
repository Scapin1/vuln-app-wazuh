<template>
  <div class="fade-in timeline-view">
    <div class="header-actions">
      <div>
        <h1 class="title">Linea del tiempo</h1>
        <p class="subtitle">Vista infografica con linea continua y slots con o sin cambios.</p>
      </div>
    </div>

    <div v-if="statusError" class="status-banner status-error">{{ statusError }}</div>
    <div v-if="statusWarning" class="status-banner status-warning">{{ statusWarning }}</div>

    <TimelineFilters
      :connections="connections"
      :agent-options="agentOpts"
      :vuln-options="vulnOpts"
      :selected-connection="selectedConnection"
      :selected-agents="selectedAgents"
      :selected-vulns="selectedVulns"
      :period="period"
      :periods="periods"
      :custom-date="customDate"
      :loading="loading"
      @update:selected-connection="selectedConnection = $event"
      @update:selected-agents="selectedAgents = $event"
      @update:selected-vulns="selectedVulns = $event"
      @update:custom-date="customDate = $event"
      @connection-change="onConnectionChange"
      @set-period="setPeriod"
      @build="buildTimeline"
    />

    <TimelineKpiStrip
      :has-built="hasBuilt || loading"
      :painted-count="paintedCount"
      :latest-snap="latestSnap"
    />

    <div v-if="loading" class="card loading-card">
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
    <div v-else-if="!hasBuilt" class="card empty-card">
      <h3>Sin datos para mostrar</h3>
      <p>Selecciona filtros y presiona "Aplicar Filtros".</p>
    </div>
    <div v-else-if="hasBuilt && filteredVulnsData.length === 0" class="card empty-card">
      <h3>Sin datos para mostrar</h3>
      <p>No se encontraron vulnerabilidades para los filtros seleccionados.</p>
    </div>
    <VulnTable v-else :vulns="filteredVulnsData" :loading="false" />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useVulnStore } from '../../application/stores/vulnStore'
import wazuhService from '../../application/services/wazuhService'
import useTimelineData from './timeline/useTimelineData'
import TimelineFilters from './timeline/components/TimelineFilters.vue'
import TimelineKpiStrip from './timeline/components/TimelineKpiStrip.vue'
import VulnTable from './timeline/components/VulnTable.vue'

const store = useVulnStore()

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
  { l: 'Dia', v: 'day' },
  { l: 'Todo', v: 'all' }
]

const connections = ref([])
const agentOpts = ref([])
const vulnOpts = ref([])
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const period = ref('30d')
const customDate = ref(new Date().toISOString().split('T')[0])
const errorBanner = ref('')

const getConnectionName = () => {
  const found = connections.value.find(conn => String(conn.id) === String(selectedConnection.value))
  return found?.name || ''
}

const {
  loading,
  loadingMessage,
  elapsedSeconds,
  fetchProgress,
  hasBuilt,
  paintedCount,
  latestSnap,
  errorMessage,
  warningMessage,
  build,
  cancelBuild,
  filteredVulnsData
} = useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  period,
  customDate,
  getConnectionName
})

const loadingBarWidth = computed(() => {
  if (fetchProgress.value.done) return 100
  return Math.min(fetchProgress.value.current * 20, 80)
})

const setPeriod = value => {
  period.value = value
}

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
      errorBanner.value = 'No se pudieron cargar agentes y CVEs para la conexion seleccionada.'
    }
  }

  // Reload data when connection changes
  await buildTimeline()
}

const buildTimeline = async () => {
  errorBanner.value = ''
  try {
    await build()
  } catch (error) {
    console.error(error)
  }
}

onMounted(async () => {
  try {
    const response = await wazuhService.getConnections()
    connections.value = Array.isArray(response.data) ? response.data : []
    // Auto-select first connection if available
    if (connections.value.length > 0) {
      selectedConnection.value = connections.value[0].id
    }
    // Auto-load timeline data
    await buildTimeline()
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar las conexiones Wazuh.'
  }
})

const statusError = computed(() => errorBanner.value || errorMessage.value)
const statusWarning = computed(() => warningMessage.value)
</script>

<style scoped>
.timeline-view {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.status-banner {
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--border);
  font-size: 0.85rem;
  font-weight: 600;
}

.status-error {
  color: var(--danger);
  background: var(--danger-bg);
  border-color: rgba(220, 38, 38, 0.3);
}

.status-warning {
  color: var(--warning);
  background: var(--warning-bg);
  border-color: rgba(217, 119, 6, 0.25);
}

.empty-card {
  min-height: 240px;
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
  flex-direction: column;
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

/* ── Loading card with progress ── */
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
  color: var(--text-muted, #475569);
  cursor: pointer;
  transition: all 0.2s;
}

.btn-cancel:hover {
  background: #fef2f2;
  border-color: #f87171;
  color: #dc2626;
}
</style>
