import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import SeverityChart from '@/presentation/views/dashboard/components/SeverityChart.vue'

// Polyfill canvas 2D context for Chart.js in jsdom
if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = () => ({
    canvas: document.createElement('canvas'),
    clearRect: () => {},
    fillRect: () => {},
    fillText: () => {},
    beginPath: () => {},
    arc: () => {},
    fill: () => {},
    stroke: () => {},
    moveTo: () => {},
    lineTo: () => {},
    closePath: () => {},
    translate: () => {},
    scale: () => {},
    rotate: () => {},
    drawImage: () => {},
    createLinearGradient: () => ({
      addColorStop: () => {}
    }),
    createRadialGradient: () => ({
      addColorStop: () => {}
    }),
    measureText: () => ({ width: 0 }),
    restore: () => {},
    save: () => {},
  })
}

describe('SeverityChart.vue', () => {
  const mockData = { CRITICAL: 3, HIGH: 2, MEDIUM: 5, LOW: 1 }

  it('renders the title', () => {
    const wrapper = mount(SeverityChart, {
      props: { data: mockData }
    })
    expect(wrapper.text()).toContain('Vulnerabilidades por Severidad')
  })

  it('computes chartData with correct labels', () => {
    const wrapper = mount(SeverityChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.labels).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  })

  it('computes chartData with correct values', () => {
    const wrapper = mount(SeverityChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].data).toEqual([3, 2, 5, 1])
  })

  it('computes chartData with correct severity colors', () => {
    const wrapper = mount(SeverityChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].backgroundColor).toEqual([
      '#dc2626',
      '#ea580c',
      '#eab308',
      '#22c55e'
    ])
  })

  it('handles all-zero data gracefully', () => {
    const emptyData = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    const wrapper = mount(SeverityChart, {
      props: { data: emptyData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].data).toEqual([0, 0, 0, 0])
    expect(chartData.labels).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  })

  it('renders a canvas element for Chart.js', () => {
    const wrapper = mount(SeverityChart, {
      props: { data: mockData }
    })
    expect(wrapper.find('.chart-stub').exists()).toBe(true)
  })

  it('handles partial data with missing keys gracefully', () => {
    const partialData = { CRITICAL: 5, LOW: 2 }
    const wrapper = mount(SeverityChart, {
      props: { data: partialData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.labels).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
    expect(chartData.datasets[0].data).toEqual([5, 0, 0, 2])
  })
})
