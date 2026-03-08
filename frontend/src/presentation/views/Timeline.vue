<template>
  <div class="fade-in timeline-view">
    <div class="header-actions">
      <div>
        <h1 class="title">Linea de Tiempo</h1>
        <p class="subtitle">Dias continuos, solo se pintan los dias con cambios.</p>
      </div>
    </div>

    <div class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label>Conexion Wazuh</label>
          <select v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="" disabled>Selecciona servidor...</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => dd.agents = false">
          <label>Equipos / Agentes</label>
          <button class="filter-input dd-btn" @click="dd.agents = !dd.agents">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>â–¼</span>
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
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => dd.vulns = false">
          <label>Vulnerabilidad</label>
          <button class="filter-input dd-btn" @click="dd.vulns = !dd.vulns">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>â–¼</span>
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
            </div>
          </div>
        </div>

        <div class="f-group">
          <label>Periodo</label>
          <div class="chip-row">
            <button v-for="p in periods" :key="p.v" class="chip" :class="{ on: period === p.v }" @click="setPeriod(p.v)">{{ p.l }}</button>
          </div>
        </div>

        <div class="f-group" v-if="period === 'day'">
          <label>Dia</label>
          <input type="date" v-model="customDate" class="filter-input">
        </div>

        <div class="f-group f-action">
          <button class="btn btn-primary" @click="build" :disabled="!selectedConnection || loading">
            {{ loading ? 'Analizando...' : 'Generar Vista' }}
          </button>
        </div>
      </div>
    </div>

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
          <button class="btn btn-outline btn-icon" @click="moveLeft" :disabled="!canMoveLeft">â—€</button>
          <button class="btn btn-outline btn-icon" @click="zoomOut" :disabled="!canZoomOut">-</button>
          <span class="zoom-badge">{{ activeZoom.label }}</span>
          <button class="btn btn-outline btn-icon" @click="zoomIn" :disabled="!canZoomIn">+</button>
          <button class="btn btn-outline btn-icon" @click="moveRight" :disabled="!canMoveRight">â–¶</button>
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
        </div>
      </div>
    </div>

    <div v-else class="card empty-card">
      <div v-if="loading" class="empty-center"><p>Escaneando historial...</p></div>
      <div v-else class="empty-center">
        <h3>Sin datos para mostrar</h3>
        <p>Selecciona filtros y presiona "Generar Vista".</p>
      </div>
    </div>

    <div v-if="modal.show" class="modal-overlay" @click.self="modal.show = false">
      <div class="modal-box fade-in">
        <div class="modal-top">
          <div>
            <h2>Detalle de {{ modal.ev.cardLabel }}</h2>
            <p class="text-muted">{{ modal.ev.details.length }} registros</p>
          </div>
          <div class="modal-top-right">
            <input type="text" v-model="modal.search" placeholder="Buscar..." class="modal-search">
            <button class="modal-close" @click="modal.show = false">&times;</button>
          </div>
        </div>
        <div class="modal-content custom-scroll">
          <table class="modal-table">
            <thead>
              <tr>
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

const connections = ref([])
const agentOpts = ref([])
const vulnOpts = ref([])
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const search = reactive({ agent: '', vuln: '' })
const dd = reactive({ agents: false, vulns: false })
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

const periods = [
  { l: '24H', v: '24h' },
  { l: '7D', v: '7d' },
  { l: '30D', v: '30d' },
  { l: 'Dia', v: 'day' },
  { l: 'Todo', v: 'all' }
]

const setPeriod = v => { period.value = v }
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
}

const build = async () => {
  if (!selectedConnection.value) return
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
}
</style>
