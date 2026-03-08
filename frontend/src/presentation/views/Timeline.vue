<template>
  <div class="fade-in timeline-view">
    <div class="header-actions">
      <div>
<<<<<<< Updated upstream
        <h1 class="title">Linea de Tiempo</h1>
        <p class="subtitle">Dias continuos, solo se pintan los dias con cambios.</p>
      </div>
    </div>

    <div class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label>Conexion Wazuh</label>
=======
        <h1 class="title">Línea de Tiempo</h1>
        <p class="subtitle">Evolución cronológica de vulnerabilidades detectadas y resueltas.</p>
      </div>
    </div>

    <!-- Panel de Filtros -->
    <div class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 7h-9m3 3V7m0-3h-4a2 2 0 00-2 2v12a2 2 0 002 2h4a2 2 0 002-2v-5"/><circle cx="12" cy="12" r="3"/></svg>
            Conexión Wazuh
          </label>
>>>>>>> Stashed changes
          <select v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="" disabled>Selecciona servidor...</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

<<<<<<< Updated upstream
        <div class="f-group popover-wrap" v-click-outside="() => dd.agents = false">
          <label>Equipos / Agentes</label>
          <button class="filter-input dd-btn" @click="dd.agents = !dd.agents">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
=======
        <!-- Equipos dropdown -->
        <div class="f-group popover-wrap" v-click-outside="() => dd.agents = false">
          <label>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            Equipos / Agentes
          </label>
          <button class="filter-input dd-btn" @click="dd.agents = !dd.agents">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6 9 12 15 18 9"/></svg>
>>>>>>> Stashed changes
          </button>
          <div v-if="dd.agents" class="dd-panel fade-in">
            <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedAgents = [...agentOpts]">Todos</span>
              <span @click="selectedAgents = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="a in filteredAgents" :key="a" class="dd-item">
                <input type="checkbox" :value="a" v-model="selectedAgents"> {{ a }}
              </label>
<<<<<<< Updated upstream
=======
              <p v-if="filteredAgents.length === 0" class="dd-empty">Sin resultados</p>
>>>>>>> Stashed changes
            </div>
          </div>
        </div>

<<<<<<< Updated upstream
        <div class="f-group popover-wrap" v-click-outside="() => dd.vulns = false">
          <label>Vulnerabilidad</label>
          <button class="filter-input dd-btn" @click="dd.vulns = !dd.vulns">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
=======
        <!-- CVE dropdown -->
        <div class="f-group popover-wrap" v-click-outside="() => dd.vulns = false">
          <label>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Vulnerabilidad
          </label>
          <button class="filter-input dd-btn" @click="dd.vulns = !dd.vulns">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6 9 12 15 18 9"/></svg>
>>>>>>> Stashed changes
          </button>
          <div v-if="dd.vulns" class="dd-panel fade-in">
            <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedVulns = [...vulnOpts]">Todas</span>
              <span @click="selectedVulns = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="c in filteredVulns" :key="c" class="dd-item">
                <input type="checkbox" :value="c" v-model="selectedVulns"> {{ c }}
              </label>
<<<<<<< Updated upstream
=======
              <p v-if="filteredVulns.length === 0" class="dd-empty">Sin resultados</p>
>>>>>>> Stashed changes
            </div>
          </div>
        </div>

<<<<<<< Updated upstream
        <div class="f-group">
          <label>Periodo</label>
=======
        <!-- Periodo -->
        <div class="f-group">
          <label>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Periodo de Análisis
          </label>
>>>>>>> Stashed changes
          <div class="chip-row">
            <button v-for="p in periods" :key="p.v" class="chip" :class="{ on: period === p.v }" @click="setPeriod(p.v)">{{ p.l }}</button>
          </div>
        </div>

<<<<<<< Updated upstream
        <div class="f-group" v-if="period === 'day'">
          <label>Dia</label>
=======
        <!-- Día específico -->
        <div class="f-group" v-if="period === 'day'">
          <label>Día</label>
>>>>>>> Stashed changes
          <input type="date" v-model="customDate" class="filter-input">
        </div>

        <div class="f-group f-action">
          <button class="btn btn-primary" @click="build" :disabled="!selectedConnection || loading">
<<<<<<< Updated upstream
=======
            <svg v-if="loading" class="spin" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
>>>>>>> Stashed changes
            {{ loading ? 'Analizando...' : 'Generar Vista' }}
          </button>
        </div>
      </div>
    </div>

<<<<<<< Updated upstream
    <div class="kpi-strip" v-if="hasBuilt">
      <div class="kpi-card">
        <span class="kpi-val">{{ paintedCount }}</span>
        <span class="kpi-label">Dias/Horas pintados</span>
      </div>
      <div class="kpi-card kpi-danger">
        <span class="kpi-val">{{ latestSnap.pending }}</span>
        <span class="kpi-label">Pendientes</span>
      </div>
      <div class="kpi-card kpi-success">
        <span class="kpi-val">{{ latestSnap.resolved }}</span>
        <span class="kpi-label">Resueltos</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-val">{{ latestSnap.total }}</span>
        <span class="kpi-label">Total</span>
      </div>
    </div>

    <div class="card timeline-card" v-if="hasBuilt && visibleSlots.length > 0">
      <div class="tl-toolbar">
        <div class="tl-toolbar-left">
          <span class="tl-year">{{ yearLabel }}</span>
          <span class="tl-info">{{ paintedCount }} con cambios / {{ allSlots.length }} slots</span>
        </div>
        <div class="tl-toolbar-right">
          <button class="btn btn-outline btn-icon" @click="moveLeft" :disabled="!canMoveLeft">◀</button>
          <button class="btn btn-outline btn-icon" @click="zoomOut" :disabled="!canZoomOut">-</button>
          <span class="zoom-badge">{{ activeZoom.label }}</span>
          <button class="btn btn-outline btn-icon" @click="zoomIn" :disabled="!canZoomIn">+</button>
          <button class="btn btn-outline btn-icon" @click="moveRight" :disabled="!canMoveRight">▶</button>
        </div>
      </div>

      <div class="tl-stage">
        <div class="tl-axis">
          <div
            v-for="(slot, i) in visibleSlots"
            :key="'axis-' + slot.startMs"
            class="tl-axis-tick"
            :style="{ left: slotLeft(i) + '%' }"
          >
            <span>{{ slot.tickLabel }}</span>
          </div>
        </div>

        <div class="tl-line"></div>

        <div
          v-for="(slot, i) in visibleSlots"
          :key="slot.startMs"
          class="tl-node"
          :class="[slot.painted ? (isAbove(i) ? 'above' : 'below') : 'plain']"
          :style="{ left: slotLeft(i) + '%' }"
        >
          <template v-if="slot.painted">
            <div class="tl-stem" :class="slot.type"></div>
            <div class="tl-card" :class="slot.type" @click="openModal(slot)">
              <div class="tl-card-badge" :class="slot.type">{{ badge(slot.type) }}</div>
              <div class="tl-card-time">{{ slot.cardLabel }}</div>
              <div class="tl-card-metrics">
                <div class="m-item"><span class="m-num">{{ slot.total }}</span><span class="m-lab">Total</span></div>
                <div class="m-item"><span class="m-num m-red">{{ slot.pending }}</span><span class="m-lab">Pend.</span></div>
                <div class="m-item"><span class="m-num m-green">{{ slot.resolved }}</span><span class="m-lab">Res.</span></div>
              </div>
            </div>
          </template>
          <div class="tl-dot" :class="slot.type"></div>
=======
    <!-- Resumen KPI -->
    <div class="kpi-strip" v-if="events.length > 0">
      <div class="kpi-card">
        <span class="kpi-val">{{ events.length }}</span>
        <span class="kpi-label">Eventos</span>
      </div>
      <div class="kpi-card kpi-danger">
        <span class="kpi-val">{{ latestSnap.pending }}</span>
        <span class="kpi-label">Pendientes (Último)</span>
      </div>
      <div class="kpi-card kpi-success">
        <span class="kpi-val">{{ latestSnap.resolved }}</span>
        <span class="kpi-label">Resueltos (Último)</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-val">{{ latestSnap.total }}</span>
        <span class="kpi-label">Total Acumulado</span>
      </div>
    </div>

    <!-- Línea de Tiempo -->
    <div class="card timeline-card" v-if="events.length > 0">
      <div class="tl-toolbar">
        <span class="tl-info">{{ events.length }} cambios detectados en el periodo</span>
        <div class="tl-legend">
          <span><i class="dot-icon detection"></i> Nueva Detección</span>
          <span><i class="dot-icon resolution"></i> Resolución</span>
          <span><i class="dot-icon mixed"></i> Ambos</span>
        </div>
      </div>

      <div class="tl-scroll custom-scroll" ref="scrollRef">
        <div class="tl-track" :style="{ width: trackWidth + 'px' }">
          <div class="tl-line"></div>

          <div v-for="(ev, i) in events" :key="i"
               class="tl-node" 
               :class="[i % 2 === 0 ? 'above' : 'below']"
               :style="{ left: nodeLeft(i) + '%' }">
            
            <div class="tl-dot" :class="ev.type">
              <span class="tl-pulse" v-if="ev.type !== 'none'"></span>
            </div>

            <div class="tl-stem" :class="ev.type"></div>

            <div class="tl-card" :class="ev.type" @click="openModal(ev)">
              <div class="tl-card-badge" :class="ev.type">
                {{ ev.type === 'detection' ? '+ NUEVO' : ev.type === 'resolution' ? '✓ RESUELTO' : ev.type === 'mixed' ? '± MIXTO' : 'CAMBIO' }}
              </div>
              <div class="tl-card-time">{{ ev.timeLabel }}</div>
              <div class="tl-card-metrics">
                <div class="m-item"><span class="m-num">{{ ev.total }}</span><span class="m-lab">Total</span></div>
                <div class="m-sep"></div>
                <div class="m-item"><span class="m-num m-red">{{ ev.pending }}</span><span class="m-lab">Pend.</span></div>
                <div class="m-sep"></div>
                <div class="m-item"><span class="m-num m-green">{{ ev.resolved }}</span><span class="m-lab">Res.</span></div>
              </div>
              <div class="tl-card-foot">
                <span>{{ ev.details.length }} vulns</span>
                <span class="tl-card-link">ver →</span>
              </div>
            </div>
          </div>
>>>>>>> Stashed changes
        </div>
      </div>
    </div>

<<<<<<< Updated upstream
    <div v-else class="card empty-card">
      <div v-if="loading" class="empty-center"><p>Escaneando historial...</p></div>
      <div v-else class="empty-center">
        <h3>Sin datos para mostrar</h3>
        <p>Selecciona filtros y presiona "Generar Vista".</p>
      </div>
    </div>

=======
    <!-- Vacío -->
    <div v-else class="card empty-card">
      <div v-if="loading" class="empty-center">
        <div class="loader-ring"></div>
        <p>Escaneando historial de vulnerabilidades...</p>
      </div>
      <div v-else class="empty-center">
        <svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="var(--border)" stroke-width="1.5"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        <h3 style="margin:1rem 0 0.5rem; font-weight:700; color:var(--text-main)">Sin datos para mostrar</h3>
        <p style="color:var(--text-muted); max-width:400px">Selecciona una conexión Wazuh, configura los filtros y haz clic en "Generar Vista" para construir la línea de tiempo.</p>
      </div>
    </div>

    <!-- Modal -->
>>>>>>> Stashed changes
    <div v-if="modal.show" class="modal-overlay" @click.self="modal.show = false">
      <div class="modal-box fade-in">
        <div class="modal-top">
          <div>
<<<<<<< Updated upstream
            <h2>Detalle de {{ modal.ev.cardLabel }}</h2>
            <p class="text-muted">{{ modal.ev.details.length }} registros</p>
=======
            <h2>Captura de Estado</h2>
            <p class="text-muted">{{ modal.ev.timeLabel }} · {{ modal.ev.details.length }} registradas · {{ getConnName() }}</p>
>>>>>>> Stashed changes
          </div>
          <div class="modal-top-right">
            <input type="text" v-model="modal.search" placeholder="Buscar..." class="modal-search">
            <button class="modal-close" @click="modal.show = false">&times;</button>
          </div>
        </div>
<<<<<<< Updated upstream
=======

        <!-- MiniKPIs en modal -->
        <div class="modal-kpis">
          <div class="mkpi"><span class="mkpi-n">{{ modal.ev.total }}</span><span class="mkpi-l">Total</span></div>
          <div class="mkpi mkpi-red"><span class="mkpi-n">{{ modal.ev.pending }}</span><span class="mkpi-l">Pendientes</span></div>
          <div class="mkpi mkpi-green"><span class="mkpi-n">{{ modal.ev.resolved }}</span><span class="mkpi-l">Resueltos</span></div>
        </div>

>>>>>>> Stashed changes
        <div class="modal-content custom-scroll">
          <table class="modal-table">
            <thead>
              <tr>
<<<<<<< Updated upstream
                <th @click="msort('connection_name')">Conexion</th>
                <th @click="msort('agent_name')">Equipo</th>
                <th @click="msort('cve_id')">CVE</th>
                <th @click="msort('severity')">Severidad</th>
                <th @click="msort('first_seen')">Detectado</th>
                <th @click="msort('status')">Estado</th>
                <th @click="msort('resolved_at')">Resolucion</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="v in modalRows" :key="v.id + '-' + v.cve_id">
                <td>{{ v.connection_name }}</td>
                <td>{{ v.agent_name }}</td>
                <td><code>{{ v.cve_id }}</code></td>
                <td>{{ v.severity }}</td>
                <td>{{ fmtDateTime(v.first_seen) }}</td>
                <td>{{ v.status === 'ACTIVE' ? 'ACTIVO' : 'RESUELTO' }}</td>
                <td>{{ v.resolved_at ? fmtDateTime(v.resolved_at) : '-' }}</td>
=======
                <th @click="msort('connection_name')">Conexión <span class="s-arr" v-if="modal.sk==='connection_name'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('agent_name')">Equipo <span class="s-arr" v-if="modal.sk==='agent_name'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('cve_id')">Vulnerabilidad <span class="s-arr" v-if="modal.sk==='cve_id'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('severity')">Severidad <span class="s-arr" v-if="modal.sk==='severity'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('first_seen')">Detectado <span class="s-arr" v-if="modal.sk==='first_seen'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('status')">Estado <span class="s-arr" v-if="modal.sk==='status'">{{ modal.so===1?'↑':'↓' }}</span></th>
                <th @click="msort('resolved_at')">Resolución <span class="s-arr" v-if="modal.sk==='resolved_at'">{{ modal.so===1?'↑':'↓' }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="v in modalRows" :key="v.id" :class="{ 'row-hot': v.status === 'ACTIVE' && v.severity === 'CRITICAL' }">
                <td>{{ v.connection_name }}</td>
                <td class="fw700">{{ v.agent_name }}</td>
                <td><code class="cve-code">{{ v.cve_id }}</code></td>
                <td><span :class="'sev ' + v.severity.toLowerCase()">{{ v.severity }}</span></td>
                <td>{{ fmtShort(v.first_seen) }}</td>
                <td><span :class="'st ' + v.status.toLowerCase()">{{ v.status === 'ACTIVE' ? 'ACTIVO' : 'RESUELTO' }}</span></td>
                <td>{{ v.resolved_at ? fmtShort(v.resolved_at) : '-' }}</td>
>>>>>>> Stashed changes
              </tr>
              <tr v-if="modalRows.length === 0"><td colspan="7" class="empty-row">Sin coincidencias</td></tr>
            </tbody>
          </table>
        </div>
        <div class="modal-bottom">
          <span>{{ modalRows.length }} de {{ modal.ev.details.length }} registros</span>
          <button class="btn btn-outline" @click="modal.show = false">Cerrar</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import wazuhService from '../../application/services/wazuhService'
import vulnService from '../../application/services/vulnService'

const vClickOutside = {
  mounted(el, binding) {
    el._co = e => { if (!el.contains(e.target)) binding.value(e) }
    document.addEventListener('click', el._co)
  },
<<<<<<< Updated upstream
  unmounted(el) {
    document.removeEventListener('click', el._co)
  }
}

const HOUR_MS = 3600000
const DAY_MS = 86400000
const zoomLevels = [
  { label: '30D', windowHours: 720, slotHours: 24 },
  { label: '15D', windowHours: 360, slotHours: 24 },
  { label: '7D', windowHours: 168, slotHours: 24 },
  { label: '3D', windowHours: 72, slotHours: 24 },
  { label: '1D', windowHours: 24, slotHours: 24 },
  { label: '12H', windowHours: 12, slotHours: 1 },
  { label: '6H', windowHours: 6, slotHours: 1 },
  { label: '3H', windowHours: 3, slotHours: 1 },
  { label: '1H', windowHours: 1, slotHours: 1 }
]

=======
  unmounted(el) { document.removeEventListener('click', el._co) }
}

>>>>>>> Stashed changes
const connections = ref([])
const agentOpts = ref([])
const vulnOpts = ref([])
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const search = reactive({ agent: '', vuln: '' })
const dd = reactive({ agents: false, vulns: false })
<<<<<<< Updated upstream
const period = ref('30d')
const customDate = ref(new Date().toISOString().split('T')[0])
const loading = ref(false)
const hasBuilt = ref(false)
const filteredVulnsData = ref([])
const changeEvents = ref([])
const latestSnap = ref({ total: 0, pending: 0, resolved: 0 })
const rangeStartMs = ref(0)
const rangeEndMs = ref(0)
const zoomLevelIndex = ref(0)
const viewStartIndex = ref(0)
=======
const period = ref('7d')
const customDate = ref(new Date().toISOString().split('T')[0])
const loading = ref(false)
const events = ref([])
const scrollRef = ref(null)
>>>>>>> Stashed changes

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
<<<<<<< Updated upstream
  { l: 'Dia', v: 'day' },
=======
  { l: 'Día', v: 'day' },
>>>>>>> Stashed changes
  { l: 'Todo', v: 'all' }
]

const setPeriod = v => { period.value = v }
<<<<<<< Updated upstream
const filteredAgents = computed(() => agentOpts.value.filter(a => a.toLowerCase().includes(search.agent.toLowerCase())))
const filteredVulns = computed(() => vulnOpts.value.filter(v => v.toLowerCase().includes(search.vuln.toLowerCase())))
const activeZoom = computed(() => zoomLevels[zoomLevelIndex.value])

const allSlots = computed(() => {
  if (!hasBuilt.value || !rangeStartMs.value || !rangeEndMs.value) return []
  const slots = []
  const slotMs = activeZoom.value.slotHours * HOUR_MS
  const totalSlotCount = Math.max(1, Math.ceil((rangeEndMs.value - rangeStartMs.value + 1) / slotMs))

  for (let idx = 0; idx < totalSlotCount; idx++) {
    const startMs = rangeStartMs.value + idx * slotMs
    const endMs = Math.min(rangeEndMs.value, startMs + slotMs - 1)
    const ev = summarizeChanges(startMs, endMs)
    const painted = ev.hasDetection || ev.hasResolution
    const type = ev.hasDetection && ev.hasResolution ? 'mixed' : ev.hasDetection ? 'detection' : ev.hasResolution ? 'resolution' : 'none'
    const snapshot = painted ? snapshotAt(endMs) : null

    slots.push({
      startMs,
      endMs,
      painted,
      type,
      total: snapshot?.total ?? 0,
      pending: snapshot?.pending ?? 0,
      resolved: snapshot?.resolved ?? 0,
      details: snapshot?.details ?? [],
      tickLabel: activeZoom.value.slotHours >= 24 ? fmtDDMM(startMs) : fmtHour(startMs),
      cardLabel: activeZoom.value.slotHours >= 24 ? `${fmtDDMM(startMs)} ${fmtYear(startMs)}` : `${fmtDDMM(startMs)} ${fmtHour(startMs)}`
    })
  }
  return slots
})

const visibleCount = computed(() => Math.max(1, Math.round(activeZoom.value.windowHours / activeZoom.value.slotHours)))
const maxViewStart = computed(() => Math.max(0, allSlots.value.length - visibleCount.value))
const visibleSlots = computed(() => allSlots.value.slice(viewStartIndex.value, viewStartIndex.value + visibleCount.value))
const paintedCount = computed(() => allSlots.value.filter(s => s.painted).length)

const yearLabel = computed(() => {
  if (!visibleSlots.value.length) return ''
  const y0 = fmtYear(visibleSlots.value[0].startMs)
  const y1 = fmtYear(visibleSlots.value[visibleSlots.value.length - 1].startMs)
  return y0 === y1 ? y0 : `${y0} - ${y1}`
})

const paintedOrders = computed(() => {
  const map = {}
  let order = 0
  visibleSlots.value.forEach((s, i) => {
    if (!s.painted) return
    map[i] = order
    order += 1
  })
  return map
})

const canMoveLeft = computed(() => viewStartIndex.value > 0)
const canMoveRight = computed(() => viewStartIndex.value < maxViewStart.value)
const canZoomIn = computed(() => zoomLevelIndex.value < zoomLevels.length - 1)
const canZoomOut = computed(() => zoomLevelIndex.value > 0)

const onConnectionChange = async () => {
  selectedAgents.value = []
  selectedVulns.value = []
  agentOpts.value = []
  vulnOpts.value = []
  if (!selectedConnection.value) return
  try {
    const res = await vulnService.getVulns({ connectionId: selectedConnection.value, limit: 2000 })
    const ag = new Set()
    const cv = new Set()
    res.data.forEach(v => {
      if (v.agent_name) ag.add(v.agent_name)
      if (v.cve_id) cv.add(v.cve_id)
    })
    agentOpts.value = Array.from(ag).sort()
    vulnOpts.value = Array.from(cv).sort()
  } catch (e) {
    console.error(e)
  }
=======

const filteredAgents = computed(() => agentOpts.value.filter(a => a.toLowerCase().includes(search.agent.toLowerCase())))
const filteredVulns = computed(() => vulnOpts.value.filter(v => v.toLowerCase().includes(search.vuln.toLowerCase())))

const latestSnap = computed(() => {
  if (events.value.length === 0) return { total: 0, pending: 0, resolved: 0 }
  return events.value[events.value.length - 1]
})

const trackWidth = computed(() => Math.max(events.value.length * 260, 900))
const nodeLeft = (i) => {
  if (events.value.length <= 1) return 50
  return 5 + (i / (events.value.length - 1)) * 90
}

const onConnectionChange = async () => {
  selectedAgents.value = []; selectedVulns.value = []
  agentOpts.value = []; vulnOpts.value = []
  if (!selectedConnection.value) return
  try {
    const res = await vulnService.getVulns({ connectionId: selectedConnection.value, limit: 2000 })
    const ag = new Set(), cv = new Set()
    res.data.forEach(v => { if (v.agent_name) ag.add(v.agent_name); cv.add(v.cve_id) })
    agentOpts.value = Array.from(ag).sort()
    vulnOpts.value = Array.from(cv).sort()
  } catch(e) {}
>>>>>>> Stashed changes
}

const build = async () => {
  if (!selectedConnection.value) return
<<<<<<< Updated upstream
  loading.value = true
  hasBuilt.value = false
  changeEvents.value = []
  filteredVulnsData.value = []

  try {
    const res = await vulnService.getVulns({ connectionId: selectedConnection.value, limit: 2000 })
    const vulns = res.data.filter(v => {
      const byAgent = selectedAgents.value.length === 0 || selectedAgents.value.includes(v.agent_name)
      const byVuln = selectedVulns.value.length === 0 || selectedVulns.value.includes(v.cve_id)
      return byAgent && byVuln
    })

    filteredVulnsData.value = vulns.map(v => ({
      ...v,
      historySorted: [...(v.history || [])].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    }))

    const { t0, t1 } = computeRange()
    rangeStartMs.value = alignHour(t0.getTime())
    rangeEndMs.value = t1.getTime()

    const events = []
    filteredVulnsData.value.forEach(v => {
      const fs = new Date(v.first_seen).getTime()
      if (fs >= rangeStartMs.value && fs <= rangeEndMs.value) events.push({ ms: fs, kind: 'detection' })
      v.historySorted.forEach(h => {
        const hm = new Date(h.timestamp).getTime()
        if (hm < rangeStartMs.value || hm > rangeEndMs.value) return
        if (h.action === 'RESOLVED') events.push({ ms: hm, kind: 'resolution' })
      })
    })
    changeEvents.value = events.sort((a, b) => a.ms - b.ms)
    latestSnap.value = snapshotAt(rangeEndMs.value)
    zoomLevelIndex.value = initialZoomForPeriod()
    viewStartIndex.value = Math.max(0, allSlots.value.length - visibleCount.value)
    hasBuilt.value = true
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

const computeRange = () => {
  const now = new Date()
  let t0 = new Date(0)
  let t1 = now
  if (period.value === '24h') t0 = new Date(now.getTime() - DAY_MS)
  if (period.value === '7d') t0 = new Date(now.getTime() - 7 * DAY_MS)
  if (period.value === '30d') t0 = new Date(now.getTime() - 30 * DAY_MS)
  if (period.value === 'day') {
    t0 = new Date(`${customDate.value}T00:00:00`)
    t1 = new Date(`${customDate.value}T23:59:59`)
  }
  return { t0, t1 }
}

const initialZoomForPeriod = () => {
  if (period.value === '7d') return 2
  if (period.value === '24h') return 4
  if (period.value === 'day') return 5
  return 0
}

const summarizeChanges = (startMs, endMs) => {
  let hasDetection = false
  let hasResolution = false
  for (const ev of changeEvents.value) {
    if (ev.ms < startMs) continue
    if (ev.ms > endMs) break
    if (ev.kind === 'detection') hasDetection = true
    if (ev.kind === 'resolution') hasResolution = true
    if (hasDetection && hasResolution) break
  }
  return { hasDetection, hasResolution }
}

const snapshotAt = (ms) => {
  let total = 0
  let pending = 0
  let resolved = 0
  const details = []

  filteredVulnsData.value.forEach(v => {
    const firstSeenMs = new Date(v.first_seen).getTime()
    if (firstSeenMs > ms) return

    let state = 'ACTIVE'
    let resolvedAt = null
    for (const h of v.historySorted) {
      const hms = new Date(h.timestamp).getTime()
      if (hms > ms) break
      if (h.action === 'RESOLVED') {
        state = 'RESOLVED'
        resolvedAt = h.timestamp
      } else {
        state = 'ACTIVE'
        resolvedAt = null
      }
    }

    total += 1
    if (state === 'ACTIVE') pending += 1
    else resolved += 1

    details.push({
      ...v,
      status: state,
      resolved_at: resolvedAt,
      connection_name: getConnName()
    })
  })

  return { total, pending, resolved, details }
}

const zoomIn = () => {
  if (!canZoomIn.value) return
  zoomLevelIndex.value += 1
  viewStartIndex.value = Math.min(viewStartIndex.value, maxViewStart.value)
}

const zoomOut = () => {
  if (!canZoomOut.value) return
  zoomLevelIndex.value -= 1
  viewStartIndex.value = Math.min(viewStartIndex.value, maxViewStart.value)
}

const moveLeft = () => {
  if (!canMoveLeft.value) return
  const step = Math.max(1, Math.floor(visibleCount.value / 2))
  viewStartIndex.value = Math.max(0, viewStartIndex.value - step)
}

const moveRight = () => {
  if (!canMoveRight.value) return
  const step = Math.max(1, Math.floor(visibleCount.value / 2))
  viewStartIndex.value = Math.min(maxViewStart.value, viewStartIndex.value + step)
}

const slotLeft = i => {
  if (visibleSlots.value.length <= 1) return 50
  return (i / (visibleSlots.value.length - 1)) * 100
}

const isAbove = i => ((paintedOrders.value[i] ?? 0) % 2) === 0
const badge = type => (type === 'detection' ? 'NUEVA' : type === 'resolution' ? 'RESUELTA' : 'MIXTO')
const alignHour = ms => Math.floor(ms / HOUR_MS) * HOUR_MS

const pad2 = n => String(n).padStart(2, '0')
const fmtDDMM = ms => {
  const d = new Date(ms)
  return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}`
}
const fmtYear = ms => String(new Date(ms).getFullYear())
const fmtHour = ms => `${pad2(new Date(ms).getHours())}:00`
const fmtDateTime = value => new Date(value).toLocaleString('es-CL', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })

const getConnName = () => connections.value.find(c => c.id === selectedConnection.value)?.name || ''

const modal = reactive({ show: false, ev: null, search: '', sk: 'status', so: 1 })
const openModal = ev => {
  modal.ev = ev
  modal.search = ''
  modal.show = true
}
const msort = k => {
  if (modal.sk === k) modal.so *= -1
  else {
    modal.sk = k
    modal.so = 1
  }
}
const modalRows = computed(() => {
  if (!modal.ev) return []
  let rows = [...modal.ev.details]
  if (modal.search) {
    const s = modal.search.toLowerCase()
    rows = rows.filter(v =>
      (v.agent_name || '').toLowerCase().includes(s) ||
      (v.cve_id || '').toLowerCase().includes(s) ||
      (v.severity || '').toLowerCase().includes(s)
    )
  }
  rows.sort((a, b) => {
    if (a[modal.sk] < b[modal.sk]) return -modal.so
    if (a[modal.sk] > b[modal.sk]) return modal.so
    return 0
  })
  return rows
})

onMounted(async () => {
  try {
    connections.value = (await wazuhService.getConnections()).data
  } catch (e) {
    console.error(e)
  }
})
</script>

<style scoped>
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: 1.2fr 1fr 1fr 1fr auto; align-items: stretch; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); }
.f-group:last-child { border-right: none; }
.f-group label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
.filter-input, .dd-btn { width: 100%; padding: 0.55rem 0.8rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); cursor: pointer; }
.f-action { justify-content: end; background: var(--bg-hover); }
.popover-wrap { position: relative; }
.dd-btn { display: flex; justify-content: space-between; }
.dd-panel { position: absolute; top: calc(100% + 6px); left: 0; width: 280px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-panel); z-index: 20; overflow: hidden; }
.dd-search { width: 100%; border: none; border-bottom: 1px solid var(--border); padding: 0.65rem 0.9rem; background: var(--bg-hover); color: var(--text-main); }
.dd-actions { display: flex; justify-content: space-between; padding: 0.5rem 0.9rem; border-bottom: 1px solid var(--border); font-size: 0.75rem; color: var(--primary); }
.dd-actions span { cursor: pointer; }
.dd-list { max-height: 220px; overflow-y: auto; }
.dd-item { display: flex; gap: 0.6rem; padding: 0.4rem 0.9rem; font-size: 0.82rem; }
.chip-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.chip { padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-dark); font-size: 0.72rem; font-weight: 700; color: var(--text-muted); cursor: pointer; }
.chip.on { background: var(--primary); border-color: var(--primary); color: #fff; }

.kpi-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.2rem; }
.kpi-card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1rem 1.2rem; }
.kpi-card.kpi-danger .kpi-val { color: var(--danger); }
.kpi-card.kpi-success .kpi-val { color: var(--success); }
.kpi-val { font-size: 1.6rem; font-weight: 800; line-height: 1; }
.kpi-label { font-size: 0.66rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; }

.timeline-card { padding: 0; overflow: hidden; }
.tl-toolbar { display: flex; justify-content: space-between; align-items: center; padding: 0.9rem 1.2rem; border-bottom: 1px solid var(--border); background: var(--bg-hover); }
.tl-toolbar-left { display: flex; gap: 1rem; align-items: center; }
.tl-year { font-weight: 800; font-size: 0.95rem; }
.tl-info { font-size: 0.78rem; color: var(--text-muted); }
.tl-toolbar-right { display: flex; align-items: center; gap: 0.4rem; }
.btn-icon { width: 34px; height: 34px; display: inline-flex; justify-content: center; align-items: center; }
.zoom-badge { min-width: 52px; text-align: center; font-weight: 800; font-size: 0.78rem; color: var(--text-muted); }

.tl-stage { position: relative; min-height: 420px; padding: 1.4rem 1rem 1rem; }
.tl-axis { position: absolute; top: 0; left: 1rem; right: 1rem; height: 22px; }
.tl-axis-tick { position: absolute; transform: translateX(-50%); font-size: 0.65rem; font-weight: 700; color: var(--text-muted); white-space: nowrap; }
.tl-line { position: absolute; top: 52%; left: 1rem; right: 1rem; height: 3px; border-radius: 99px; transform: translateY(-50%); background: linear-gradient(90deg, var(--border) 0%, var(--primary) 50%, var(--border) 100%); }

.tl-node { position: absolute; top: 52%; transform: translate(-50%, -50%); width: 180px; display: flex; flex-direction: column; align-items: center; }
.tl-node.above { transform: translate(-50%, -100%); }
.tl-node.below { transform: translate(-50%, 0%); }
.tl-node.above .tl-card { margin-bottom: 0.5rem; }
.tl-node.below .tl-card { margin-top: 0.5rem; }
.tl-node.plain { width: 24px; }
.tl-dot { width: 12px; height: 12px; border-radius: 50%; border: 2px solid var(--border); background: var(--bg-panel); z-index: 2; }
.tl-dot.detection { border-color: var(--danger); background: var(--danger-bg); }
.tl-dot.resolution { border-color: var(--success); background: var(--success-bg); }
.tl-dot.mixed { border-color: var(--warning); background: var(--warning-bg); }
.tl-stem { width: 2px; height: 28px; background: var(--border); }
.tl-stem.detection { background: var(--danger); }
.tl-stem.resolution { background: var(--success); }
.tl-stem.mixed { background: var(--warning); }

.tl-card { width: 168px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-card); cursor: pointer; overflow: hidden; box-shadow: var(--shadow-sm); }
.tl-card:hover { border-color: var(--primary); }
.tl-card-badge { text-align: center; font-size: 0.58rem; font-weight: 800; padding: 0.3rem 0; }
.tl-card-badge.detection { color: var(--danger); background: var(--danger-bg); }
.tl-card-badge.resolution { color: var(--success); background: var(--success-bg); }
.tl-card-badge.mixed { color: var(--warning); background: var(--warning-bg); }
.tl-card-time { text-align: center; font-size: 0.7rem; font-weight: 700; padding: 0.5rem 0.4rem 0.25rem; }
.tl-card-metrics { display: grid; grid-template-columns: repeat(3, 1fr); padding: 0.2rem 0.4rem 0.55rem; }
.m-item { text-align: center; }
.m-num { font-size: 0.9rem; font-weight: 800; }
.m-lab { font-size: 0.54rem; color: var(--text-muted); text-transform: uppercase; }
.m-red { color: var(--danger); }
.m-green { color: var(--success); }

.empty-card { min-height: 240px; display: flex; justify-content: center; align-items: center; text-align: center; }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.45); z-index: 200; display: flex; align-items: center; justify-content: center; padding: 1rem; }
.modal-box { width: 100%; max-width: 1000px; max-height: 88vh; background: var(--bg-panel); border-radius: var(--radius-lg); display: flex; flex-direction: column; overflow: hidden; }
.modal-top { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 1rem 1.2rem; border-bottom: 1px solid var(--border); }
.modal-search { padding: 0.45rem 0.8rem; border: 1px solid var(--border); border-radius: 20px; background: var(--bg-hover); color: var(--text-main); }
.modal-close { border: none; background: transparent; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; }
.modal-top-right { display: flex; align-items: center; gap: 0.6rem; }
.modal-content { overflow: auto; }
.modal-table { width: 100%; border-collapse: collapse; }
.modal-table th, .modal-table td { padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
.modal-table th { font-size: 0.67rem; text-transform: uppercase; color: var(--text-muted); background: var(--bg-hover); position: sticky; top: 0; }
.modal-table th { cursor: pointer; }
.empty-row { text-align: center; color: var(--text-muted); }
.modal-bottom { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1.2rem; border-top: 1px solid var(--border); font-size: 0.78rem; color: var(--text-muted); }

@media (max-width: 1100px) {
  .filter-row { grid-template-columns: 1fr 1fr; }
  .f-group { border-right: none; border-bottom: 1px solid var(--border); }
  .kpi-strip { grid-template-columns: 1fr 1fr; }
  .tl-stage { min-height: 500px; }
=======
  loading.value = true; events.value = []
  try {
    const res = await vulnService.getVulns({ connectionId: selectedConnection.value, limit: 2000 })
    let vulns = res.data.filter(v => {
      const ma = selectedAgents.value.length === 0 || selectedAgents.value.includes(v.agent_name)
      const mv = selectedVulns.value.length === 0 || selectedVulns.value.includes(v.cve_id)
      return ma && mv
    })

    const now = new Date()
    let t0 = new Date(0), t1 = now
    if (period.value === '24h') t0 = new Date(now - 86400000)
    if (period.value === '7d') t0 = new Date(now - 7 * 86400000)
    if (period.value === '30d') t0 = new Date(now - 30 * 86400000)
    if (period.value === 'day') {
      t0 = new Date(customDate.value + 'T00:00:00')
      t1 = new Date(customDate.value + 'T23:59:59')
    }

    const tps = new Set()
    vulns.forEach(v => {
      const fs = new Date(v.first_seen)
      if (fs >= t0 && fs <= t1) tps.add(v.first_seen)
      if (v.history) v.history.forEach(h => {
        const ht = new Date(h.timestamp)
        if (ht >= t0 && ht <= t1) tps.add(h.timestamp)
      })
    })

    const sorted = Array.from(tps).sort((a,b) => new Date(a) - new Date(b))
    const result = []
    let last = { t: -1, p: -1, r: -1 }

    sorted.forEach(ts => {
      const d = new Date(ts)
      let total = 0, pending = 0, resolved = 0, details = []
      vulns.forEach(v => {
        if (new Date(v.first_seen) > d) return
        let state = 'ACTIVE', resolved_at = null
        if (v.history) {
          const h = v.history.filter(x => new Date(x.timestamp) <= d).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp))
          if (h.length && h[0].action === 'RESOLVED') {
            state = 'RESOLVED'
            resolved_at = h[0].timestamp
          }
        }
        total++; state === 'ACTIVE' ? pending++ : resolved++
        details.push({ 
          ...v, 
          status: state, 
          resolved_at,
          connection_name: getConnName()
        })
      })

      const isNew = vulns.some(v => v.first_seen === ts)
      const isFix = vulns.some(v => v.history?.some(h => h.timestamp === ts && h.action === 'RESOLVED'))
      let type = 'none'
      if (isNew && isFix) type = 'mixed'
      else if (isNew) type = 'detection'
      else if (isFix) type = 'resolution'

      if (total !== last.t || pending !== last.p || resolved !== last.r) {
        result.push({ timestamp: ts, timeLabel: fmtFull(ts), total, pending, resolved, type, details })
        last = { t: total, p: pending, r: resolved }
      }
    })

    events.value = result
  } catch(e) { console.error(e) }
  finally { loading.value = false }
}

const modal = reactive({ show: false, ev: null, search: '', sk: 'status', so: 1 })
const openModal = ev => { modal.ev = ev; modal.search = ''; modal.show = true }
const msort = k => { if (modal.sk === k) modal.so *= -1; else { modal.sk = k; modal.so = 1 } }
const modalRows = computed(() => {
  if (!modal.ev) return []
  let d = [...modal.ev.details]
  if (modal.search) {
    const s = modal.search.toLowerCase()
    d = d.filter(v => v.agent_name.toLowerCase().includes(s) || v.cve_id.toLowerCase().includes(s) || v.severity.toLowerCase().includes(s))
  }
  d.sort((a,b) => { if (a[modal.sk] < b[modal.sk]) return -modal.so; if (a[modal.sk] > b[modal.sk]) return modal.so; return 0 })
  return d
})

const getConnName = () => connections.value.find(c => c.id === selectedConnection.value)?.name || ''
const fmtShort = s => new Date(s).toLocaleDateString('es-ES', { day: '2-digit', month: 'short' })
const fmtFull = s => new Date(s).toLocaleString('es-ES', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

onMounted(async () => { try { connections.value = (await wazuhService.getConnections()).data } catch(e){} })
</script>

<style scoped>
/* ── Panel de Filtros ── */
.filter-panel {
  padding: 0;
  margin-bottom: 1.5rem;
  overflow: visible;
}

.filter-row {
  display: grid;
  grid-template-columns: 1.3fr 1fr 1fr 1.2fr auto;
  gap: 0;
  align-items: stretch;
}

.f-group {
  display: flex;
  flex-direction: column;
  padding: 1.1rem 1.35rem;
  border-right: 1px solid var(--border);
  position: relative;
}

.f-group:last-child { border-right: none; }

.f-group label {
  font-size: 0.65rem;
  font-weight: 800;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.f-group .filter-input,
.f-group .dd-btn {
  width: 100%;
  padding: 0.55rem 0.85rem;
  border-radius: var(--radius-sm);
  background-color: var(--bg-dark);
  border: 1px solid transparent;
  color: var(--text-main);
  font-size: 0.85rem;
  font-weight: 600;
  transition: var(--transition);
  outline: none;
  cursor: pointer;
}

.f-group .filter-input:focus,
.f-group .filter-input:hover,
.f-group .dd-btn:hover {
  border-color: var(--primary);
  background-color: var(--bg-hover);
  box-shadow: 0 0 0 3px var(--primary-glow);
}

.f-action {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.1rem 1.35rem;
  border-right: none;
  background: var(--bg-hover);
  border-left: 1px solid var(--border);
}

.f-action .btn { width: 100%; white-space: nowrap; }

/* Dropdown Multi-select */
.popover-wrap { position: relative; }
.dd-btn {
  display: flex;
  justify-content: space-between;
  align-items: center;
  min-width: 0;
}

.dd-panel {
  position: absolute;
  top: calc(100% + 10px);
  left: -1px;
  width: 300px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  box-shadow: 0 12px 28px rgba(0,0,0,0.12), 0 2px 4px rgba(0,0,0,0.04);
  z-index: 100;
  padding: 0;
  overflow: hidden;
}

.dd-search {
  width: 100%;
  padding: 0.7rem 1rem;
  border: none;
  border-bottom: 1px solid var(--border);
  font-size: 0.82rem;
  background: var(--bg-hover);
  outline: none;
  color: var(--text-main);
}
.dd-search:focus { background: #fff; }

.dd-actions {
  display: flex;
  justify-content: space-between;
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--primary);
  cursor: pointer;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg-hover);
}
.dd-actions span:hover { text-decoration: underline; }

.dd-list { max-height: 220px; overflow-y: auto; padding: 0.25rem 0; }
.dd-item {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.45rem 1rem;
  cursor: pointer;
  font-size: 0.82rem;
  transition: background 0.1s;
}
.dd-item:hover { background: var(--bg-hover); }
.dd-item input[type="checkbox"] { accent-color: var(--primary); }
.dd-empty { font-size: 0.75rem; color: var(--text-muted); text-align: center; padding: 1.5rem 1rem; }

/* Period Chips */
.chip-row { display: flex; gap: 0.35rem; flex-wrap: wrap; }
.chip {
  padding: 0.45rem 0.9rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-dark);
  font-size: 0.75rem;
  font-weight: 700;
  cursor: pointer;
  color: var(--text-muted);
  transition: var(--transition);
  letter-spacing: 0.02em;
}
.chip.on {
  background: var(--primary);
  color: #fff;
  border-color: var(--primary);
  box-shadow: 0 2px 6px var(--primary-glow);
}
.chip:hover:not(.on) {
  border-color: var(--primary);
  color: var(--primary);
  background: var(--bg-hover);
}

@media (max-width: 900px) {
  .filter-row { grid-template-columns: 1fr 1fr; }
  .f-group { border-right: none; border-bottom: 1px solid var(--border); }
  .f-action { border-left: none; }
}

/* ── KPI Strip ── */
.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1.25rem;
  margin-bottom: 1.5rem;
}

.kpi-card {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 1.25rem 1.5rem;
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  transition: var(--transition);
  border-left: 4px solid var(--text-muted);
}

.kpi-card:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md);
}

.kpi-card.kpi-danger { border-left-color: var(--danger); }
.kpi-card.kpi-success { border-left-color: var(--success); }
.kpi-card:first-child { border-left-color: var(--primary); }

.kpi-val {
  display: block;
  font-size: 1.75rem;
  font-weight: 800;
  color: var(--text-main);
  line-height: 1.2;
}

.kpi-label {
  font-size: 0.65rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-top: 0.25rem;
}

.kpi-danger .kpi-val { color: var(--danger); }
.kpi-success .kpi-val { color: var(--success); }

/* ── Timeline ── */
.timeline-card { padding: 0; overflow: hidden; }
.tl-toolbar { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); background: var(--bg-hover); }
.tl-info { font-size: 0.8rem; font-weight: 700; color: var(--text-muted); }
.tl-legend { display: flex; gap: 1.5rem; font-size: 0.72rem; font-weight: 600; color: var(--text-muted); }
.tl-legend span { display: flex; align-items: center; gap: 6px; }
.dot-icon { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.dot-icon.detection { background: var(--danger); }
.dot-icon.resolution { background: var(--success); }
.dot-icon.mixed { background: var(--warning); }

.tl-scroll { overflow-x: auto; padding: 2.5rem 1.5rem 2.5rem; }
.tl-track { position: relative; min-height: 320px; }

.tl-line { 
  position: absolute; top: 50%; left: 0; right: 0; height: 3px; 
  background: linear-gradient(90deg, var(--border) 0%, var(--primary) 50%, var(--border) 100%);
  transform: translateY(-50%); border-radius: 3px;
}

/* Nodos */
.tl-node { 
  position: absolute; transform: translateX(-50%);
  display: flex; flex-direction: column; align-items: center;
  width: 210px;
}
.tl-node.above { top: 0; }
.tl-node.above .tl-card { order: 1; }
.tl-node.above .tl-stem { order: 2; }
.tl-node.above .tl-dot { order: 3; }
.tl-node.below { top: 50%; }
.tl-node.below .tl-dot { order: 1; }
.tl-node.below .tl-stem { order: 2; }
.tl-node.below .tl-card { order: 3; }

.tl-dot { 
  width: 18px; height: 18px; border-radius: 50%; 
  background: var(--bg-panel); border: 3px solid var(--border);
  position: relative; z-index: 10; flex-shrink: 0;
  transition: var(--transition);
}
.tl-dot.detection { border-color: var(--danger); background: #fef2f2; }
.tl-dot.resolution { border-color: var(--success); background: #ecfdf5; }
.tl-dot.mixed { border-color: var(--warning); background: #fffbeb; }

.tl-pulse {
  position: absolute; top: -5px; left: -5px; width: 24px; height: 24px; border-radius: 50%;
  animation: pulse 2s ease-out infinite;
}
.tl-dot.detection .tl-pulse { background: var(--danger); }
.tl-dot.resolution .tl-pulse { background: var(--success); }
.tl-dot.mixed .tl-pulse { background: var(--warning); }
@keyframes pulse { 0% { transform: scale(0.6); opacity: 0.5; } 100% { transform: scale(2.2); opacity: 0; } }

.tl-stem { width: 2px; height: 35px; background: var(--border); flex-shrink: 0; }
.tl-stem.detection { background: var(--danger-bg); }
.tl-stem.resolution { background: var(--success-bg); }

/* Card */
.tl-card {
  width: 195px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-md); padding: 0; cursor: pointer;
  box-shadow: var(--shadow-sm); transition: var(--transition); flex-shrink: 0;
  overflow: hidden;
}
.tl-card:hover { transform: translateY(-5px); box-shadow: var(--shadow-md); border-color: var(--primary); }

.tl-card-badge { 
  font-size: 0.6rem; font-weight: 800; text-align: center; 
  padding: 4px 0; text-transform: uppercase; letter-spacing: 0.05em;
}
.tl-card-badge.detection { background: var(--danger-bg); color: var(--danger); }
.tl-card-badge.resolution { background: var(--success-bg); color: var(--success); }
.tl-card-badge.mixed { background: var(--warning-bg); color: var(--warning); }
.tl-card-badge.none { background: var(--bg-hover); color: var(--text-muted); }

.tl-card-time { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); padding: 0.6rem 0.75rem 0; text-align: center; }

.tl-card-metrics { display: flex; justify-content: center; align-items: center; padding: 0.5rem 0.75rem; gap: 0; }
.m-item { text-align: center; flex: 1; }
.m-num { display: block; font-size: 1.1rem; font-weight: 800; color: var(--text-main); line-height: 1; }
.m-lab { display: block; font-size: 0.52rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-top: 2px; }
.m-red { color: var(--danger) !important; }
.m-green { color: var(--success) !important; }
.m-sep { width: 1px; height: 22px; background: var(--border); margin: 0 2px; }

.tl-card-foot { display: flex; justify-content: space-between; padding: 0.5rem 0.75rem; border-top: 1px solid var(--border); font-size: 0.65rem; color: var(--text-muted); }
.tl-card-link { color: var(--primary); font-weight: 700; }

/* Empty */
.empty-card { min-height: 300px; display: flex; align-items: center; justify-content: center; text-align: center; }
.empty-center { text-align: center; }
.loader-ring { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 1rem; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Modal ── */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.45); backdrop-filter: blur(3px); z-index: 200; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
.modal-box { background: var(--bg-panel); width: 100%; max-width: 980px; max-height: 88vh; border-radius: var(--radius-lg); display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); }
.modal-top { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.modal-top h2 { font-size: 1.15rem; font-weight: 700; margin: 0; }
.modal-top .text-muted { font-size: 0.8rem; color: var(--text-muted); margin: 0.25rem 0 0; }
.modal-top-right { display: flex; align-items: center; gap: 0.75rem; }
.modal-search { padding: 0.4rem 0.85rem; border: 1px solid var(--border); border-radius: 20px; font-size: 0.8rem; width: 210px; background: var(--bg-hover); outline: none; }
.modal-close { background: none; border: none; font-size: 1.5rem; color: var(--text-muted); cursor: pointer; }

.modal-kpis { display: flex; gap: 1rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); background: var(--bg-hover); }
.mkpi { flex: 1; display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 1rem; border-radius: var(--radius-sm); background: var(--bg-panel); border: 1px solid var(--border); }
.mkpi-n { font-size: 1.25rem; font-weight: 800; color: var(--text-main); }
.mkpi-l { font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }
.mkpi-red .mkpi-n { color: var(--danger); }
.mkpi-green .mkpi-n { color: var(--success); }

.modal-content { flex: 1; overflow-y: auto; }
.modal-table { width: 100%; border-collapse: collapse; }
.modal-table th { text-align: left; padding: 0.85rem 1.25rem; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); background: var(--bg-hover); cursor: pointer; user-select: none; position: sticky; top: 0; z-index: 5; }
.modal-table th:hover { color: var(--primary); }
.s-arr { color: var(--primary); font-weight: 800; }
.modal-table td { padding: 0.85rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.82rem; }
.modal-table tr:hover { background: var(--bg-hover); }
.fw700 { font-weight: 700; }
.cve-code { font-weight: 600; color: var(--primary); background: var(--primary-glow); padding: 2px 6px; border-radius: 4px; font-size: 0.78rem; }
.row-hot { background: #fef2f2 !important; }
.empty-row { text-align: center; color: var(--text-muted); padding: 2rem !important; }

.sev { font-size: 0.6rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
.sev.critical { background: #fee2e2; color: #991b1b; }
.sev.high { background: #ffedd5; color: #9a3412; }
.sev.medium { background: #fef3c7; color: #92400e; }
.sev.low { background: #dbeafe; color: #1e40af; }

.st { font-size: 0.6rem; font-weight: 800; padding: 3px 10px; border-radius: 20px; text-transform: uppercase; }
.st.active { background: var(--danger-bg); color: var(--danger); }
.st.resolved { background: var(--success-bg); color: var(--success); }

.modal-bottom { padding: 0.85rem 1.5rem; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: var(--text-muted); }

.custom-scroll::-webkit-scrollbar { width: 6px; height: 6px; }
.custom-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }

@media (max-width: 900px) {
  .filter-row { flex-direction: column; align-items: stretch; }
  .f-action { margin-left: 0; }
  .kpi-strip { grid-template-columns: repeat(2, 1fr); }
>>>>>>> Stashed changes
}
</style>
