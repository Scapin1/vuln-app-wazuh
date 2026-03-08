<template>
  <div class="fade-in">
    <!-- Header Area -->
    <div class="header-actions">
      <div>
        <h1 class="title">Panorama de Amenazas</h1>
        <p class="subtitle">Visualiza y gestiona el inventario de vulnerabilidades reportado por Wazuh.</p>
      </div>
      <div>
        <button class="btn btn-secondary" @click="showFilters = !showFilters">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
          </svg>
          {{ showFilters ? 'Ocultar' : 'Filtros' }}
        </button>
        <button class="btn btn-primary" @click="syncVulns" :disabled="syncing">
          <svg v-if="syncing" class="spin" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-9.5l1.75 1.93"></path></svg>
          {{ syncing ? 'Sincronizando con Wazuh...' : 'Forzar Sincronización' }}
        </button>
      </div>
    </div>

    <!-- Filter Tray -->
    <div v-show="showFilters" class="filter-tray fade-in">
      <div class="filter-grid">
        <div class="filter-item">
          <label>Estado</label>
          <input v-model="filters.estado" type="text" placeholder="NUEVO, ACTIVO..." class="filter-input">
        </div>
        <div class="filter-item">
          <label>Severidad</label>
          <input v-model="filters.severidad" type="text" placeholder="CRITICAL, HIGH..." class="filter-input">
        </div>
        <div class="filter-item">
          <label>CVE ID</label>
          <input v-model="filters.cveId" type="text" placeholder="CVE-2023-..." class="filter-input">
        </div>
        <div class="filter-item">
          <label>Agente</label>
          <input v-model="filters.agente" type="text" placeholder="Nombre del agente..." class="filter-input">
        </div>
        <div class="filter-item">
          <label>Software Afectado</label>
          <input v-model="filters.software" type="text" placeholder="Nombre del paquete..." class="filter-input">
        </div>
        <div class="filter-item" style="grid-column: span 2;">
          <label>Rango de Fechas</label>
          <div style="display: flex; gap: 0.5rem;">
            <div style="flex: 1;">
              <input v-model="filters.startDate" type="date" class="filter-input" style="width: 100%;">
            </div>
            <div style="flex: 1;">
              <input v-model="filters.endDate" type="date" class="filter-input" style="width: 100%;">
            </div>
          </div>
        </div>
      </div>
      <div class="filter-actions">
        <button class="btn btn-outline" @click="clearFilters">Limpiar Filtros</button>
      </div>
    </div>

    <!-- Error/Loading states -->
    <div v-if="error" class="alert alert-danger fade-in">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      {{ error }}
    </div>

    <div v-if="loading" class="empty-state">
      <div class="spinner-box">
        <svg class="spin" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
      </div>
      <p>Cargando datos del cluster...</p>
    </div>

    <!-- Table -->
    <div v-else class="card" style="padding: 0;">
      <div class="table-wrapper">
        <table v-if="vulns.length > 0">
          <thead>
            <tr>
              <th width="10%" @click="sortBy('first_seen')">
                Estado
                <span v-if="sortKey === 'first_seen'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th width="12%" @click="sortBy('severity')">
                Severidad
                <span v-if="sortKey === 'severity'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th width="15%" @click="sortBy('cve_id')">
                CVE ID
                <span v-if="sortKey === 'cve_id'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th width="15%" @click="sortBy('agent_name')">
                Agente
                <span v-if="sortKey === 'agent_name'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th width="28%" @click="sortBy('package_name')">
                Software Afectado
                <span v-if="sortKey === 'package_name'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th width="20%" @click="sortBy('last_seen')">
                Línea de Vida
                <span v-if="sortKey === 'last_seen'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vuln in sortedVulns" :key="vuln.id">
              <td>
                <span v-if="isNew(vuln.first_seen)" class="badge badge-new">
                  <span class="pulse-dot"></span> NUEVO
                </span>
                <span v-else class="badge" style="background-color: var(--bg-hover); color: var(--text-muted);">
                  ACTIVO
                </span>
              </td>
              <td>
                <span :class="getSeverityClass(vuln.severity)">
                  {{ (vuln.severity || 'UNKNOWN').toUpperCase() }}
                </span>
              </td>
              <td class="font-medium text-black">{{ vuln.cve_id || 'N/A' }}</td>
              <td>
                <div class="agent-info">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
                  <span>{{ vuln.agent_name || vuln.agent_id || 'N/A' }}</span>
                </div>
              </td>
              <td>
                <div class="package-info">
                  <span class="pkg-name">{{ vuln.package_name }}</span>
                  <span class="pkg-version">v{{ vuln.package_version }}</span>
                </div>
              </td>
              <td>
                <div class="timeline-info">
                  <div class="timeline-row">
                    <span class="timeline-label">Detectado:</span>
                    <span>{{ formatDate(vuln.first_seen) }}</span>
                  </div>
                  <div class="timeline-row">
                    <span class="timeline-label">Última vez:</span>
                    <span>{{ formatDate(vuln.last_seen) }}</span>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty-state" style="padding: 4rem 2rem;">
          <div class="shield-box">
             <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
          </div>
          <p style="color: var(--text-main); font-weight: 500; font-size: 1.1rem; margin-bottom: 0.5rem;">No hay conexiones activas</p>
          <p style="color: var(--text-muted); font-size: 0.9rem;">El sistema no reporta conexiones activas actualmente.</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import vulnService from '../../application/services/vulnService'

const vulns = ref([])
const loading = ref(true)
const syncing = ref(false)
const error = ref('')
const sortKey = ref('last_seen')
const sortOrder = ref('desc')
const showFilters = ref(false)
const filters = ref({
  estado: '',
  severidad: '',
  cveId: '',
  agente: '',
  software: '',
  startDate: '',
  endDate: ''
})

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1 // low or unknown
}

const compareValues = (a, b, key) => {
  let aVal = a[key]
  let bVal = b[key]

  if (key === 'first_seen' || key === 'last_seen') {
    aVal = aVal ? new Date(aVal).getTime() : 0
    bVal = bVal ? new Date(bVal).getTime() : 0
    return aVal - bVal
  } else if (key === 'severity') {
    aVal = getSeverityLevel(aVal)
    bVal = getSeverityLevel(bVal)
    return aVal - bVal
  } else {
    aVal = aVal || ''
    bVal = bVal || ''
    if (typeof aVal === 'string') {
      return aVal.toLowerCase().localeCompare(bVal.toLowerCase())
    }
    return aVal - bVal
  }
}

const estadoOptions = computed(() => {
  const estados = new Set()
  vulns.value.forEach(vuln => {
    const estado = isNew(vuln.first_seen) ? 'NUEVO' : 'ACTIVO'
    estados.add(estado)
  })
  return Array.from(estados).sort()
})

const severidadOptions = computed(() => {
  const severidades = new Set()
  vulns.value.forEach(vuln => {
    const severidad = (vuln.severity || 'UNKNOWN').toUpperCase()
    severidades.add(severidad)
  })
  return Array.from(severidades).sort((a, b) => {
    // Sort by severity level for better UX
    const levelA = getSeverityLevel(a.toLowerCase())
    const levelB = getSeverityLevel(b.toLowerCase())
    return levelB - levelA // Higher severity first
  })
})

const filteredVulns = computed(() => {
  return vulns.value.filter(vuln => {
    const estadoText = isNew(vuln.first_seen) ? 'NUEVO' : 'ACTIVO'
    const severidadText = (vuln.severity || 'UNKNOWN').toUpperCase()
    const cveText = vuln.cve_id || 'N/A'
    const agenteText = vuln.agent_name || vuln.agent_id || 'N/A'
    const softwareText = vuln.package_name || ''

    // Date filtering
    let dateMatch = true
    if (filters.value.startDate || filters.value.endDate) {
      const firstSeen = vuln.first_seen ? new Date(vuln.first_seen) : null
      const lastSeen = vuln.last_seen ? new Date(vuln.last_seen) : null
      const start = filters.value.startDate ? new Date(filters.value.startDate) : null
      const end = filters.value.endDate ? new Date(filters.value.endDate) : null

      if (start && end) {
        dateMatch = (firstSeen && firstSeen >= start && firstSeen <= end) || (lastSeen && lastSeen >= start && lastSeen <= end)
      } else if (start) {
        dateMatch = (firstSeen && firstSeen >= start) || (lastSeen && lastSeen >= start)
      } else if (end) {
        dateMatch = (firstSeen && firstSeen <= end) || (lastSeen && lastSeen <= end)
      }
    }

    return (
      (!filters.value.estado || estadoText.toLowerCase().includes(filters.value.estado.toLowerCase())) &&
      (!filters.value.severidad || severidadText.toLowerCase().includes(filters.value.severidad.toLowerCase())) &&
      (!filters.value.cveId || cveText.toLowerCase().includes(filters.value.cveId.toLowerCase())) &&
      (!filters.value.agente || agenteText.toLowerCase().includes(filters.value.agente.toLowerCase())) &&
      (!filters.value.software || softwareText.toLowerCase().includes(filters.value.software.toLowerCase())) &&
      dateMatch
    )
  })
})

const sortedVulns = computed(() => {
  if (!sortKey.value) return filteredVulns.value
  return [...filteredVulns.value].sort((a, b) => {
    const cmp = compareValues(a, b, sortKey.value)
    return sortOrder.value === 'asc' ? cmp : -cmp
  })
})

const sortBy = (key) => {
  if (sortKey.value !== key) {
    sortKey.value = key
    sortOrder.value = 'asc'
  } else if (sortOrder.value === 'asc') {
    sortOrder.value = 'desc'
  } else {
    sortKey.value = ''
    sortOrder.value = ''
  }
}

const clearFilters = () => {
  filters.value = {
    estado: '',
    severidad: '',
    cveId: '',
    agente: '',
    software: '',
    startDate: '',
    endDate: ''
  }
}

const fetchVulns = async () => {
  loading.value = true
  error.value = ''
  try {
    const res = await vulnService.getVulns()
    vulns.value = res.data
  } catch (err) {
    error.value = 'Error al cargar los datos de vulnerabilidades.'
  } finally {
    loading.value = false
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

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const d = new Date(dateString)
  return d.toLocaleDateString('es-ES', { 
    day: '2-digit', month: 'short', year: 'numeric', 
    hour: '2-digit', minute: '2-digit' 
  })
}

const isNew = (firstSeenDate) => {
  if (!firstSeenDate) return false
  const now = new Date()
  const firstSeen = new Date(firstSeenDate)
  const diffTime = Math.abs(now - firstSeen)
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  return diffDays <= 1
}

const getSeverityClass = (severity) => {
  if (!severity) return 'badge badge-low'
  const s = severity.toLowerCase()
  if (['critical', 'high', 'alta', 'critica'].includes(s)) return 'badge badge-critical'
  if (['medium', 'media'].includes(s)) return 'badge badge-medium'
  return 'badge badge-low'
}

onMounted(() => {
  fetchVulns()
})
</script>

<style scoped>
.header-actions {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

th {
  cursor: pointer;
}

.sort-indicator {
  margin-left: 0.5rem;
  display: inline-block;
  transition: transform 0.2s ease;
}

.rotate-180 {
  transform: rotate(180deg);
}

.filter-tray {
  background-color: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-item label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-main);
}

.filter-input {
  padding: 0.5rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background-color: var(--bg-input);
  color: var(--text-main);
  font-size: 0.9rem;
}

.filter-input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
}

.filter-actions {
  display: flex;
  justify-content: flex-end;
}

.btn-outline {
  background-color: transparent;
  border: 1px solid var(--border);
  color: var(--text-main);
  padding: 0.5rem 1rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.2s ease;
}

.btn-outline:hover {
  background-color: var(--bg-hover);
  border-color: var(--text-muted);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 3rem;
  color: var(--text-muted);
}

.spinner-box {
  margin-bottom: 1rem;
}

.shield-box {
  width: 80px;
  height: 80px;
  background-color: var(--success-bg);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 1.5rem;
  border: 4px solid rgba(16, 185, 129, 0.1);
}

.font-medium {
  font-weight: 500;
}
.text-black {
  color: var(--text-main);
  font-weight: 400;
}

.agent-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-muted);
}

.package-info {
  display: flex;
  flex-direction: column;
}

.pkg-name {
  color: var(--text-main);
  font-weight: 500;
}

.pkg-version {
  color: var(--text-muted);
  font-size: 0.8rem;
}

.timeline-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.timeline-row {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
}

.timeline-label {
  color: #6b7280;
}

.pulse-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: var(--primary);
  margin-right: 0.35rem;
  box-shadow: 0 0 0 0 rgba(135, 197, 62, 0.7);
  animation: pulse 1.5s infinite;
}

@keyframes pulse {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(135, 197, 62, 0.7); }
  70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(135, 197, 62, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(135, 197, 62, 0); }
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
</style>
