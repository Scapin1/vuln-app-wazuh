<template>
  <div class="card area-chart-card">
    <div class="chart-header">
      <h3 class="chart-title">Volumen de Vulnerabilidades a lo largo del tiempo</h3>
      <div class="chart-legend">
        <div class="legend-item">
          <span class="legend-dot pending"></span>
          <span>Pendientes</span>
        </div>
        <div class="legend-item">
          <span class="legend-dot resolved"></span>
          <span>Resueltas</span>
        </div>
      </div>
    </div>
    <div v-if="!areaData.length" class="chart-empty">
      <p>Sin datos para mostrar. Genera la línea de tiempo primero.</p>
    </div>
    <div v-else ref="chartContainer" class="chart-container"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, nextTick, onBeforeUnmount } from 'vue'
import * as d3 from 'd3'

const props = defineProps({
  areaData: { type: Array, required: true }
})

const chartContainer = ref(null)
let resizeObserver = null

const renderChart = () => {
  if (!chartContainer.value || !props.areaData.length) return

  const container = chartContainer.value
  container.innerHTML = ''

  const width = container.clientWidth
  if (width === 0) return

  const margin = { top: 20, right: 30, bottom: 40, left: 50 }
  const innerWidth = width - margin.left - margin.right
  const innerHeight = 300 - margin.top - margin.bottom

  const svg = d3.select(container)
    .append('svg')
    .attr('width', width)
    .attr('height', 300)
    .append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`)

  // Coerce to numbers for D3 stack
  const data = props.areaData.map(d => ({
    date: new Date(d.date),
    pending: Number(d.pending) || 0,
    resolved: Number(d.resolved) || 0,
    total: Number(d.total) || 0
  }))

  const x = d3.scaleTime()
    .domain(d3.extent(data, d => d.date))
    .nice()
    .range([0, innerWidth])

  const maxVal = d3.max(data, d => d.pending + d.resolved) || 100
  const y = d3.scaleLinear()
    .domain([0, maxVal])
    .nice()
    .range([innerHeight, 0])

  const stack = d3.stack()
    .keys(['pending', 'resolved'])
    .offset(d3.stackOffsetNone)

  const stackedData = stack(data)

  const area = d3.area()
    .x(d => x(d.data.date))
    .y0(d => y(d[0]))
    .y1(d => y(d[1]))
    .curve(d3.curveMonotoneX)

  const colors = {
    pending: '#ba1a1a',
    resolved: '#6ca42c'
  }

  svg.selectAll('.layer')
    .data(stackedData)
    .join('path')
    .attr('class', 'layer')
    .attr('d', area)
    .attr('fill', d => colors[d.key])
    .attr('opacity', 0.85)

  // X axis
  svg.append('g')
    .attr('transform', `translate(0,${innerHeight})`)
    .call(d3.axisBottom(x).ticks(Math.min(6, data.length)).tickFormat(d3.timeFormat('%d %b')))
    .selectAll('text')
    .style('fill', '#94a3b8')
    .style('font-size', '11px')

  // Y axis
  svg.append('g')
    .call(d3.axisLeft(y).ticks(5))
    .selectAll('text')
    .style('fill', '#94a3b8')
    .style('font-size', '11px')

  // Axis lines
  svg.selectAll('.domain')
    .style('stroke', '#e2e8f0')
  svg.selectAll('.tick line')
    .style('stroke', '#e2e8f0')
}

onMounted(() => {
  nextTick(() => {
    renderChart()
    resizeObserver = new ResizeObserver(() => {
      renderChart()
    })
    if (chartContainer.value) {
      resizeObserver.observe(chartContainer.value)
    }
  })
})

watch(() => props.areaData, () => {
  nextTick(() => renderChart())
}, { deep: true })

onBeforeUnmount(() => {
  if (resizeObserver) resizeObserver.disconnect()
})
</script>

<style scoped>
.area-chart-card {
  background: var(--surface, #ffffff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: var(--radius-lg, 8px);
  padding: 1.5rem;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.chart-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text, #1e293b);
  margin: 0;
}

.chart-legend {
  display: flex;
  gap: 1rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-muted, #64748b);
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.legend-dot.pending { background-color: #ba1a1a; }
.legend-dot.resolved { background-color: #6ca42c; }

.chart-container {
  width: 100%;
  height: 300px;
}

.chart-empty {
  height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted, #94a3b8);
  font-size: 0.9rem;
}
</style>
