import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import StatusChart from '@/presentation/views/dashboard/components/StatusChart.vue'

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

describe('StatusChart.vue', () => {
  const mockData = { Detected: 8, Resolved: 4, 'Re-emerged': 2 }

  it('renders the title', () => {
    const wrapper = mount(StatusChart, {
      props: { data: mockData }
    })
    expect(wrapper.text()).toContain('Estado de Vulnerabilidades')
  })

  it('computes chartData with correct labels', () => {
    const wrapper = mount(StatusChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.labels).toEqual(['Detected', 'Resolved', 'Re-emerged'])
  })

  it('computes chartData with correct values', () => {
    const wrapper = mount(StatusChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].data).toEqual([8, 4, 2])
  })

  it('computes chartData with correct status colors', () => {
    const wrapper = mount(StatusChart, {
      props: { data: mockData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].backgroundColor).toEqual([
      '#dc2626',
      '#22c55e',
      '#eab308'
    ])
  })

  it('handles all-zero data gracefully', () => {
    const emptyData = { Detected: 0, Resolved: 0, 'Re-emerged': 0 }
    const wrapper = mount(StatusChart, {
      props: { data: emptyData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].data).toEqual([0, 0, 0])
    expect(chartData.labels).toEqual(['Detected', 'Resolved', 'Re-emerged'])
  })

  it('renders a canvas element for Chart.js', () => {
    const wrapper = mount(StatusChart, {
      props: { data: mockData }
    })
    expect(wrapper.find('canvas').exists()).toBe(true)
  })

  it('handles partial data with missing keys gracefully', () => {
    const partialData = { Detected: 10 }
    const wrapper = mount(StatusChart, {
      props: { data: partialData }
    })
    const chartData = wrapper.vm.chartData
    expect(chartData.datasets[0].data).toEqual([10, 0, 0])
  })
})
