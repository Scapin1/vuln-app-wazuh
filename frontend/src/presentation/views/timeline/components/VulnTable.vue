<template>
  <div class="card" style="padding: 0;">
    <div class="table-wrapper">
      <div v-if="totalPages > 1" class="pagination-header">
        <span class="pagination-info">
          Mostrando {{ (currentPage - 1) * itemsPerPage + 1 }} - {{ Math.min(currentPage * itemsPerPage, sortedVulns.length) }} de {{ sortedVulns.length }} vulnerabilidades
        </span>
        <div class="pagination-nav">
          <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 5 páginas" aria-label="Retroceder 5 páginas">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
          </button>
          <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
          </button>
          <div class="page-numbers">
            <template v-for="(item, idx) in visiblePages" :key="`top-${item}-${idx}`">
              <button
                v-if="typeof item === 'number'"
                class="btn-page"
                :class="{ 'active': currentPage === item }"
                @click="currentPage = item"
              >
                {{ item }}
              </button>
              <span v-else class="pagination-ellipsis">...</span>
            </template>
          </div>
          <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </button>
          <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 5 páginas" aria-label="Avanzar 5 páginas">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
          </button>
        </div>
      </div>

      <table v-if="vulns.length > 0" class="vuln-table">
        <caption class="visually-hidden">
          Tabla de vulnerabilidades con severidad, CVE, agente, software afectado y linea de tiempo de actividad.
        </caption>
        <thead>
          <tr>
            <th style="width: 10%;" @click="sortBy('connection_name')">
              Conexión Wazuh
              <span v-if="sortKey === 'connection_name'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th style="width: 12%;" @click="sortBy('severity')">
              Severidad
              <span v-if="sortKey === 'severity'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th style="width: 8%;" @click="sortBy('score_base')">
              Score CVSS
              <span v-if="sortKey === 'score_base'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th class="col-cve" @click="sortBy('cve_id')">
              CVE ID
              <span v-if="sortKey === 'cve_id'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th class="col-agent" @click="sortBy('agent_name')">
              Agente
              <span v-if="sortKey === 'agent_name'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th class="col-package" @click="sortBy('package_name')">
              Software Afectado
              <span v-if="sortKey === 'package_name'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
            <th class="col-timeline" @click="sortBy('last_seen')">
              Línea de Tiempo
              <span v-if="sortKey === 'last_seen'" class="sort-indicator">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                  <path d="M7 14l5-5 5 5z"/>
                </svg>
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="vuln in paginatedVulns" :key="vuln.id">
            <td>{{ vuln.connection_name || connectionName || '-' }}</td>
            <td>
              <span :class="getSeverityClass(vuln.severity)">
                {{ (vuln.severity || 'UNKNOWN').toUpperCase() }}
              </span>
            </td>
            <td class="font-medium score-cell">
              {{ vuln.score_base != null ? vuln.score_base.toFixed(1) : 'N/A' }}
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
              <div class="visual-timeline">
                <!-- Punto de Detección -->
                <div class="timeline-point start">
                  <div class="point-marker">
                    <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                  </div>
                  <div class="point-content">
                    <span class="point-title">Detectado</span>
                    <span class="point-time" :title="formatDate(vuln.first_seen)">{{ timeAgo(vuln.first_seen) }}</span>
                  </div>
                </div>

                <!-- Línea Conectora -->
                <div class="timeline-track">
                  <div class="track-progress" :style="{ width: getTimelineProgress(vuln) + '%' }"></div>
                </div>

                <!-- Punto de Última Vista -->
                <div class="timeline-point end">
                  <div class="point-marker" :class="{ 'pulse-radar': isRecentlySeen(vuln.last_seen) }">
                    <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                  </div>
                  <div class="point-content">
                    <span class="point-title">Última actividad</span>
                    <span class="point-time" :title="formatDate(vuln.last_seen)">{{ timeAgo(vuln.last_seen) }}</span>
                  </div>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
      </table>

      <!-- Controles de Paginación Abajo -->
      <div v-if="totalPages > 1" class="pagination-controls-bottom">
        <div class="pagination-nav" style="margin-left: auto;">
          <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 5 páginas" aria-label="Retroceder 5 páginas">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
          </button>
          <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
          </button>
          <div class="page-numbers">
            <template v-for="(item, idx) in visiblePages" :key="`bottom-${item}-${idx}`">
              <button
                v-if="typeof item === 'number'"
                class="btn-page"
                :class="{ 'active': currentPage === item }"
                @click="currentPage = item"
              >
                {{ item }}
              </button>
              <span v-else class="pagination-ellipsis">...</span>
            </template>
          </div>
          <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </button>
          <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 5 páginas" aria-label="Avanzar 5 páginas">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
          </button>
        </div>
      </div>

      <div v-if="vulns.length === 0 && !loading" class="empty-state" style="padding: 4rem 2rem;">
        <div class="shield-box">
           <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
        </div>
        <p style="color: var(--text-main); font-weight: 500; font-size: 1.1rem; margin-bottom: 0.5rem;">No hay conexiones activas</p>
        <p style="color: var(--text-muted); font-size: 0.9rem;">El sistema no reporta conexiones activas actualmente.</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { parseServerDate } from '../timelineFormatters'

const props = defineProps({
  vulns: { type: Array, required: true },
  loading: { type: Boolean, default: false },
  connectionName: { type: String, default: '' },
  syncStart: { type: String, default: null },
  syncEnd: { type: String, default: null }
})

// Sorting state
const sortKey = ref('last_seen')
const sortOrder = ref('desc')

// Pagination state
const currentPage = ref(1)
const itemsPerPage = 50
const pageJump = 10

// ── Helpers ──

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1
}

const compareValues = (a, b, key) => {
  let aVal = a[key]
  let bVal = b[key]

  if (key === 'first_seen' || key === 'last_seen') {
    aVal = aVal ? parseServerDate(aVal).getTime() : 0
    bVal = bVal ? parseServerDate(bVal).getTime() : 0
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

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const d = parseServerDate(dateString)
  return d.toLocaleDateString('es-CL', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })
}

const getSeverityClass = (severity) => {
  if (!severity) return 'badge badge-low'
  const s = severity.toLowerCase()
  if (['critical', 'high', 'alta', 'critica'].includes(s)) return 'badge badge-critical'
  if (['medium', 'media'].includes(s)) return 'badge badge-medium'
  return 'badge badge-low'
}

const getSeverityBadgeClass = (severity) => {
  const s = severity.toLowerCase()
  if (['critical', 'critica'].includes(s)) return 'badge-critical'
  if (['high', 'alta'].includes(s)) return 'badge-high'
  if (['medium', 'media'].includes(s)) return 'badge-medium'
  return 'badge-low'
}

const isRecentlySeen = (lastSeenDate) => {
  if (!lastSeenDate) return false
  const now = new Date()
  const lastSeen = parseServerDate(lastSeenDate)
  const diffMinutes = Math.floor((now - lastSeen) / (1000 * 60))
  return diffMinutes <= 60
}

const getTimelineProgress = (vuln) => {
  if (!vuln.first_seen || !vuln.last_seen) return 0
  const first = parseServerDate(vuln.first_seen).getTime()
  const last = parseServerDate(vuln.last_seen).getTime()
  const now = Date.now()

  if (last === first) return 0

  const totalDuration = now - first
  const activeDuration = last - first

  return Math.min(100, Math.max(5, (activeDuration / totalDuration) * 100))
}

const timeAgo = (date) => {
  if (!date) return 'N/A'
  const seconds = Math.floor((Date.now() - parseServerDate(date)) / 1000)

  let interval = seconds / 31536000
  if (interval > 1) return `Hace ${Math.floor(interval)} años`

  interval = seconds / 2592000
  if (interval > 1) return `Hace ${Math.floor(interval)} meses`

  interval = seconds / 86400
  if (interval > 1) return `Hace ${Math.floor(interval)} días`

  interval = seconds / 3600
  if (interval > 1) return `Hace ${Math.floor(interval)} horas`

  interval = seconds / 60
  if (interval > 1) return `Hace ${Math.floor(interval)} min`

  return 'Justo ahora'
}

// ── Date interval filter (from Gantt click) ──

const isInSyncInterval = (vuln) => {
  if (!props.syncStart) return true

  const syncStartMs = new Date(props.syncStart).getTime()
  const syncEndMs = props.syncEnd ? new Date(props.syncEnd).getTime() : Date.now()

  // Filter by last_seen being within the sync interval
  const lastSeenMs = new Date(vuln.last_seen).getTime()
  return lastSeenMs >= syncStartMs && lastSeenMs <= syncEndMs
}

// ── Sorting ──

const sortedVulns = computed(() => {
  let result = [...props.vulns]

  // Apply sync interval filter if set (from Gantt click)
  if (props.syncStart) {
    result = result.filter(isInSyncInterval)
  }

  if (!sortKey.value) return result
  return result.sort((a, b) => {
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

// ── Pagination ──

const totalPages = computed(() => {
  return Math.ceil(sortedVulns.value.length / itemsPerPage)
})

const paginatedVulns = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return sortedVulns.value.slice(start, end)
})

const visiblePages = computed(() => {
  const pages = []
  const total = totalPages.value
  const current = currentPage.value
  const maxNumericButtons = 7

  if (total <= maxNumericButtons) {
    for (let i = 1; i <= total; i++) pages.push(i)
    return pages
  }

  const middleSlots = maxNumericButtons - 2
  pages.push(1)

  let start = Math.max(2, current - Math.floor(middleSlots / 2))
  let end = start + middleSlots - 1

  if (end > total - 1) {
    end = total - 1
    start = end - middleSlots + 1
  }

  if (start > 2) pages.push('left-ellipsis')
  for (let i = start; i <= end; i++) pages.push(i)
  if (end < total - 1) pages.push('right-ellipsis')

  pages.push(total)
  return pages
})

const nextPage = () => {
  if (currentPage.value < totalPages.value) currentPage.value++
}

const prevPage = () => {
  if (currentPage.value > 1) currentPage.value--
}

const jumpBackward = () => {
  currentPage.value = Math.max(1, currentPage.value - pageJump)
}

const jumpForward = () => {
  currentPage.value = Math.min(totalPages.value, currentPage.value + pageJump)
}

// Reset to page 1 when sort changes
watch(sortKey, () => { currentPage.value = 1 })
watch(sortOrder, () => { currentPage.value = 1 })

// Reset to page 1 when vulns change
watch(() => props.vulns, () => { currentPage.value = 1 })
</script>

<style scoped>
.visual-timeline {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem 0;
  min-width: 180px;
}

.timeline-point {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.point-marker {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.start .point-marker {
  background-color: #f3f4f6;
  color: #475569;
  border: 1px solid #e5e7eb;
}

.end .point-marker {
  background-color: rgba(59, 130, 246, 0.1);
  color: #1e40af;
  border: 1px solid rgba(59, 130, 246, 0.2);
}

.point-content {
  display: flex;
  flex-direction: column;
  line-height: 1.2;
}

.point-title {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.025em;
  color: #475569;
  font-weight: 600;
}

.point-time {
  font-size: 0.85rem;
  color: var(--text-main);
  font-weight: 500;
}

.timeline-track {
  background-color: #f3f4f6;
  border-radius: 2px;
  margin-left: 10px;
  width: 2px;
  height: 12px;
  position: relative;
}

.track-progress {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  background-color: #3b82f6;
  border-radius: 2px;
}

.pulse-radar {
  position: relative;
}

.pulse-radar::after {
  content: '';
  position: absolute;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background-color: #3b82f6;
  opacity: 0.4;
  animation: radar-pulse 2s infinite;
}

@keyframes radar-pulse {
  0% { transform: scale(1); opacity: 0.4; }
  100% { transform: scale(2.5); opacity: 0; }
}

th {
  cursor: pointer;
}

.sort-indicator {
  margin-left: 0.5rem;
  display: inline-block;
  transition: transform 0.2s ease;
}

.vuln-table .col-severity { width: 12%; }
.vuln-table .col-cve { width: 15%; }
.vuln-table .col-agent { width: 15%; }
.vuln-table .col-package { width: 28%; }
.vuln-table .col-timeline { width: 20%; }

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.rotate-180 {
  transform: rotate(180deg);
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

/* PAGINACION */
.pagination-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.5rem;
  border-bottom: 1px solid var(--border);
  background-color: var(--bg-panel);
}

.pagination-info {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-muted);
}

.pagination-controls-bottom {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--border);
  background-color: var(--bg-card);
}

.pagination-nav {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.page-numbers {
  display: flex;
  gap: 0.2rem;
}

.btn-icon-page {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-icon-page:hover:not(:disabled) {
  background-color: var(--bg-hover);
  border-color: var(--text-muted);
}

.btn-icon-page:disabled {
  opacity: 0.3;
  cursor: not-allowed;
  border-color: transparent;
}

.btn-page {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 28px;
  padding: 0 0.25rem;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-page:hover:not(.active) {
  background-color: var(--bg-hover);
  color: var(--text-main);
}

.btn-page.active {
  background-color: var(--primary);
  color: #000;
}

.pagination-ellipsis {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  color: var(--text-muted);
  font-size: 0.8rem;
  font-weight: 600;
}

.badge {
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
}

.badge-critical {
  background: #fee2e2;
  color: #991b1b;
}

.badge-high {
  background: #ffedd5;
  color: #7c2d12;
}

.badge-medium {
  background: #fef9c3;
  color: #713f12;
}

.badge-low {
  background: #dbeafe;
  color: #1e3a5e;
}
</style>
