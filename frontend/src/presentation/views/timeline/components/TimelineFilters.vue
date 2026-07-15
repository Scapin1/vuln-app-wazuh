<template>
  <div class="card filter-panel" :class="{ compact }">
    <div class="filter-row">
      <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
        <label>Conexión Wazuh</label>
        <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'connections' ? '' : 'connections'">
          <span>{{ selectedConnectionName || 'Selecciona servidor...' }}</span>
          <span>▼</span>
        </button>
        <div v-if="activeDropdown === 'connections'" class="dd-panel fade-in">
          <div class="dd-list custom-scroll">
            <button 
              v-for="conn in connections" 
              :key="conn.id" 
              class="dd-item dd-item-btn"
              :class="{ 'dd-item-selected': String(conn.id) === String(connectionModel) }"
              @click="selectConnection(conn.id)"
            >
              {{ conn.name }}
            </button>
          </div>
        </div>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
        <label>Equipos / Agentes</label>
        <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'agents' ? '' : 'agents'">
          <span :class="selectedAgentsModel.length ? 'sel-badge' : ''">{{ selectedAgentsModel.length ? selectedAgentsModel.length + ' sel.' : 'Todos' }}</span>
          <span>▼</span>
        </button>
        <div v-if="activeDropdown === 'agents'" class="dd-panel fade-in">
          <input type="text" id="search-agent" v-model="search.agent" placeholder="Buscar agente..." class="dd-search" aria-label="Buscar agente">
          <div class="dd-actions">
            <span @click="selectedAgentsModel = [...agentOptions]">Todos</span>
            <span @click="selectedAgentsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="agent in filteredAgents" :key="agent" class="dd-item">
              <input type="checkbox" :value="agent" v-model="selectedAgentsModel"> {{ agent }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
        <label>Vulnerabilidad</label>
        <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'vulns' ? '' : 'vulns'">
          <span :class="selectedVulnsModel.length ? 'sel-badge' : ''">{{ selectedVulnsModel.length ? selectedVulnsModel.length + ' sel.' : 'Todas' }}</span>
          <span>▼</span>
        </button>
        <div v-if="activeDropdown === 'vulns'" class="dd-panel fade-in">
          <input type="text" id="search-vuln" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search" aria-label="Buscar CVE">
          <div class="dd-actions">
            <span @click="selectedVulnsModel = [...vulnOptions]">Todas</span>
            <span @click="selectedVulnsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="vuln in filteredVulns" :key="vuln" class="dd-item">
              <input type="checkbox" :value="vuln" v-model="selectedVulnsModel"> {{ vuln }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group" v-if="severityOptions?.length">
        <span class="f-group-label">Criticidad</span>
        <div class="chip-row">
          <button
            v-for="sev in severityOptions"
            :key="sev.value"
            class="chip"
            :class="{ on: selectedSeveritiesModel.includes(sev.value) }"
            @click="toggleSeverity(sev.value)"
          >
            {{ sev.label }}
          </button>
        </div>
      </div>

      <div class="f-group">
        <label>Periodo</label>
        <div class="chip-row">
          <button
            v-for="periodOption in periods"
            :key="periodOption.v"
            class="chip"
            :class="{ on: period === periodOption.v }"
            @click="emit('set-period', periodOption.v)"
          >
            {{ periodOption.l }}
          </button>
        </div>
      </div>

      <div class="f-group day-datetime-group" v-if="period === 'day'">
        <label for="custom-date">Dia</label>
        <div class="dt-row">
          <input id="custom-date" type="date" :value="datePart" @input="onDateChange" class="filter-input">
          <select id="filter-hour" :value="hourPart" @change="onHourChange" class="filter-input time-sel" aria-label="Hora">
            <option v-for="h in HOURS" :key="h" :value="h">{{ h }}</option>
          </select>
          <select id="filter-minute" :value="minutePart" @change="onMinuteChange" class="filter-input time-sel" aria-label="Minuto">
            <option v-for="m in MINUTES" :key="m" :value="m">{{ m }}</option>
          </select>
        </div>
      </div>

      <div class="f-group f-action">
        <button class="btn btn-primary" @click="emit('build')" :disabled="!selectedConnection || loading">
          {{ loading ? 'Analizando...' : 'Aplicar Filtros' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'

const props = defineProps({
  /** customDate puede ser "YYYY-MM-DD" (solo fecha) o "YYYY-MM-DDTHH:MM" (con hora) */
  connections: { type: Array, required: true },
  agentOptions: { type: Array, required: true },
  vulnOptions: { type: Array, required: true },
  selectedConnection: { type: [String, Number], default: '' },
  selectedAgents: { type: Array, required: true },
  selectedVulns: { type: Array, required: true },
  severityOptions: { type: Array, default: null },
  selectedSeverities: { type: Array, default: () => [] },
  period: { type: String, required: true },
  periods: { type: Array, required: true },
  customDate: { type: String, required: true },
  loading: { type: Boolean, default: false },
  compact: { type: Boolean, default: false }
})

const emit = defineEmits([
  'update:selectedConnection',
  'update:selectedAgents',
  'update:selectedVulns',
  'update:selectedSeverities',
  'update:customDate',
  'connection-change',
  'set-period',
  'build'
])

const connectionModel = computed({
  get: () => props.selectedConnection,
  set: value => emit('update:selectedConnection', value)
})

const selectedAgentsModel = computed({
  get: () => props.selectedAgents,
  set: value => emit('update:selectedAgents', value)
})

const selectedVulnsModel = computed({
  get: () => props.selectedVulns,
  set: value => emit('update:selectedVulns', value)
})

const selectedConnectionName = computed(() => {
  const found = props.connections.find(c => String(c.id) === String(props.selectedConnection))
  return found?.name || ''
})

const selectConnection = (connId) => {
  connectionModel.value = connId
  activeDropdown.value = ''
  emit('connection-change')
}

const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'))
const MINUTES = Array.from({ length: 60 }, (_, i) => String(i).padStart(2, '0'))

const datePart = computed(() => props.customDate?.split('T')[0] || '')
const hourPart = computed(() => props.customDate?.split('T')[1]?.split(':')[0] || '00')
const minutePart = computed(() => props.customDate?.split('T')[1]?.split(':')[1] || '00')

const emitDatetime = (date, hour, minute) => {
  emit('update:customDate', `${date || datePart.value}T${hour || hourPart.value}:${minute || minutePart.value}`)
}
const onDateChange = (e) => emitDatetime(e.target.value)
const onHourChange = (e) => emitDatetime(null, e.target.value)
const onMinuteChange = (e) => emitDatetime(null, null, e.target.value)

const search = reactive({ agent: '', vuln: '' })
const activeDropdown = ref('')

const filteredAgents = computed(() =>
  props.agentOptions.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredVulns = computed(() =>
  props.vulnOptions.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)

const selectedSeveritiesModel = computed({
  get: () => props.selectedSeverities,
  set: value => emit('update:selectedSeverities', value)
})

const toggleSeverity = (sev) => {
  const current = [...props.selectedSeverities]
  const idx = current.indexOf(sev)
  if (idx >= 0) current.splice(idx, 1)
  else current.push(sev)
  emit('update:selectedSeverities', current)
}
</script>

<style scoped>
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); align-items: stretch; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); }
.f-group:last-child { border-right: none; }
.f-group label,
.f-group .f-group-label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
.filter-input, .dd-btn { width: 100%; padding: 0.55rem 0.8rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); cursor: pointer; }
.f-action { justify-content: end; background: var(--bg-hover); }
.popover-wrap { position: relative; }
.dd-btn { display: flex; justify-content: space-between; }
.dd-panel { position: absolute; top: calc(100% + 6px); left: 0; width: 280px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-panel); z-index: 20; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
.dd-search { width: 100%; border: none; border-bottom: 1px solid var(--border); padding: 0.65rem 0.9rem; background: var(--bg-hover); color: var(--text-main); }
.dd-actions { display: flex; justify-content: space-between; padding: 0.5rem 0.9rem; border-bottom: 1px solid var(--border); font-size: 0.75rem; color: var(--primary); }
.dd-actions span { cursor: pointer; }
.dd-list { max-height: 220px; overflow-y: auto; }
.dd-item { display: flex; gap: 0.6rem; padding: 0.4rem 0.9rem; font-size: 0.82rem; }
.dd-item:hover { background: var(--bg-hover); }
.dd-item-btn { width: 100%; text-align: left; background: none; border: none; color: var(--text-main); cursor: pointer; }
.dd-item-selected { background: var(--primary-bg); color: var(--primary); font-weight: 600; }
.chip-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.chip { padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-dark); font-size: 0.72rem; font-weight: 700; color: var(--text-muted); cursor: pointer; }
.chip.on { background: var(--primary); border-color: var(--primary); color: #fff; }
.sel-badge { background: var(--primary-bg); color: var(--primary); border-radius: 999px; padding: 0.1rem 0.45rem; font-size: 0.72rem; font-weight: 700; }
.day-datetime-group { min-width: 320px; }
.dt-row { display: flex; gap: 0.35rem; align-items: stretch; }
.dt-row .filter-input { flex: 1; min-width: 0; }
.time-sel { flex: 0 0 70px; cursor: pointer; appearance: auto; }

@media (max-width: 1400px) {
  .filter-row { grid-template-columns: 1fr 1fr; }
  .f-group { border-right: none; border-bottom: 1px solid var(--border); }
}

/* ── Compact mode ── */
.compact .filter-row {
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
}

.compact .f-group {
  padding: 0.5rem 0.8rem;
}

.compact .f-group label {
  margin-bottom: 0.3rem;
}

.compact .filter-input,
.compact .dd-btn {
  padding: 0.4rem 0.6rem;
  font-size: 0.75rem;
}

.compact .chip {
  padding: 0.25rem 0.55rem;
  font-size: 0.68rem;
}

.compact .dd-panel {
  width: 240px;
}
</style>
