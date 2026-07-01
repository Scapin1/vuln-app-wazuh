<template>
  <div class="chart-card">
    <h3 class="chart-title">Vulnerabilidades por Severidad</h3>
    <div class="chart-wrapper">
      <Pie :data="chartData" :options="chartOptions" />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Pie } from 'vue-chartjs'
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

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#eab308',
  LOW: '#22c55e'
}

const chartData = computed(() => ({
  labels: SEVERITY_ORDER,
  datasets: [
    {
      data: SEVERITY_ORDER.map(sev => props.data[sev] ?? 0),
      backgroundColor: SEVERITY_ORDER.map(sev => SEVERITY_COLORS[sev]),
      borderWidth: 1,
      borderColor: '#ffffff'
    }
  ]
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: true,
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
