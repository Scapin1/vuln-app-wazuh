<template>
  <div class="chart-card">
    <h3 class="chart-title">Estado de Vulnerabilidades</h3>
    <div class="chart-wrapper">
      <Doughnut :data="chartData" :options="chartOptions" />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend
} from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps({
  data: {
    type: Object,
    required: true
  }
})

const STATUS_ORDER = ['Detected', 'Resolved', 'Re-emerged']

const STATUS_COLORS = {
  Detected: '#dc2626',
  Resolved: '#22c55e',
  'Re-emerged': '#eab308'
}

const chartData = computed(() => ({
  labels: STATUS_ORDER,
  datasets: [
    {
      data: STATUS_ORDER.map(status => props.data[status] ?? 0),
      backgroundColor: STATUS_ORDER.map(status => STATUS_COLORS[status]),
      borderWidth: 1,
      borderColor: '#ffffff'
    }
  ]
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: true,
  cutout: '60%',
  plugins: {
    legend: {
      position: 'bottom',
      labels: {
        padding: 16,
        usePointStyle: true
      }
    },
    tooltip: {
      callbacks: {
        label: (context) => {
          const total = context.dataset.data.reduce((a, b) => a + b, 0)
          const value = context.parsed
          const pct = total > 0 ? ((value / total) * 100).toFixed(1) : 0
          return ` ${context.label}: ${value} (${pct}%)`
        }
      }
    }
  }
}
</script>

<style scoped>
.chart-card {
  background: var(--bg-card, #ffffff);
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 0.75rem;
  padding: 1.25rem;
  height: 100%;
}

.chart-title {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-muted, #6b7280);
  text-transform: uppercase;
  letter-spacing: 0.025em;
  margin: 0 0 1rem 0;
}

.chart-wrapper {
  max-width: 280px;
  margin: 0 auto;
}
</style>
