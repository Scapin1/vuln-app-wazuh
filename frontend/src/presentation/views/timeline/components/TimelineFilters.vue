<template>
  <div class="card filter-panel">
    <div class="filter-row">
      <div class="f-group">
        <label>Conexion Wazuh</label>
        <select v-model="connectionModel" @change="emit('connection-change')" class="filter-input">
          <option value="" disabled>Selecciona servidor...</option>
          <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
        </select>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (activeDropdown = '')">
        <label>Equipos / Agentes</label>
        <button class="filter-input dd-btn" @click="activeDropdown = activeDropdown === 'agents' ? '' : 'agents'">
          <span :class="selectedAgentsModel.length ? 'sel-badge' : ''">{{ selectedAgentsModel.length ? selectedAgentsModel.length + ' sel.' : 'Todos' }}</span>
          <span>▼</span>
        </button>
        <div v-if="activeDropdown === 'agents'" class="dd-panel fade-in">
          <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
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
          <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
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

      <div class="f-group" v-if="period === 'day'">
        <label>Dia</label>
        <input type="date" v-model="customDateModel" class="filter-input">
      </div>

      <div class="f-group f-action">
        <button class="btn btn-primary" @click="emit('build')" :disabled="!selectedConnection || loading">
          {{ loading ? 'Analizando...' : 'Generar Vista' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'

const props = defineProps({
  connections: { type: Array, required: true },
  agentOptions: { type: Array, required: true },
  vulnOptions: { type: Array, required: true },
  selectedConnection: { type: [String, Number], default: '' },
  selectedAgents: { type: Array, required: true },
  selectedVulns: { type: Array, required: true },
  period: { type: String, required: true },
  periods: { type: Array, required: true },
  customDate: { type: String, required: true },
  loading: { type: Boolean, default: false }
})

const emit = defineEmits([
  'update:selectedConnection',
  'update:selectedAgents',
  'update:selectedVulns',
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

const customDateModel = computed({
  get: () => props.customDate,
  set: value => emit('update:customDate', value)
})

const search = reactive({ agent: '', vuln: '' })
const activeDropdown = ref('')

const filteredAgents = computed(() =>
  props.agentOptions.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredVulns = computed(() =>
  props.vulnOptions.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)
</script>

<style scoped>
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); align-items: stretch; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); }
.f-group:last-child { border-right: none; }
.f-group label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
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
.chip-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.chip { padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-dark); font-size: 0.72rem; font-weight: 700; color: var(--text-muted); cursor: pointer; }
.chip.on { background: var(--primary); border-color: var(--primary); color: #fff; }
.sel-badge { background: var(--primary-bg); color: var(--primary); border-radius: 999px; padding: 0.1rem 0.45rem; font-size: 0.72rem; font-weight: 700; }

@media (max-width: 1400px) {
  .filter-row { grid-template-columns: 1fr 1fr; }
  .f-group { border-right: none; border-bottom: 1px solid var(--border); }
}
</style>
