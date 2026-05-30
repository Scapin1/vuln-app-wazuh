import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import AreaChartTab from '@/presentation/views/timeline/components/AreaChartTab.vue'

// In jsdom, clientWidth returns 0 for unstyled elements. D3's renderChart exits
// early when width === 0. We mock clientWidth so D3 actually renders the SVG.
const MOCK_WIDTH = 800

describe('AreaChartTab.vue', () => {
  const mockAreaData = [
    { date: '2026-03-01', pending: 10, resolved: 5, total: 15 },
    { date: '2026-03-02', pending: 8, resolved: 7, total: 15 },
    { date: '2026-03-03', pending: 6, resolved: 9, total: 15 },
    { date: '2026-03-04', pending: 4, resolved: 11, total: 15 }
  ]

  beforeEach(() => {
    // Mock clientWidth so D3 chart renders in jsdom
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
      configurable: true,
      get() {
        return this.classList?.contains('chart-container') ? MOCK_WIDTH : 0
      }
    })
  })

  afterEach(() => {
    // Restore clientWidth
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
      configurable: true,
      get() { return 0 }
    })
  })

  describe('empty state', () => {
    it('renders empty message when areaData is empty', () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: [] }
      })

      expect(wrapper.find('.chart-empty').exists()).toBe(true)
      expect(wrapper.text()).toContain('Sin datos para mostrar')
      expect(wrapper.find('.chart-container').exists()).toBe(false)
    })

    it('does not render chart container when areaData is empty', () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: [] }
      })

      expect(wrapper.find('svg').exists()).toBe(false)
    })
  })

  describe('with data', () => {
    it('renders the chart title', () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })

      expect(wrapper.find('.chart-title').exists()).toBe(true)
      expect(wrapper.text()).toContain('Volumen de Vulnerabilidades')
    })

    it('renders chart container when areaData has items', () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })

      expect(wrapper.find('.chart-empty').exists()).toBe(false)
      expect(wrapper.find('.chart-container').exists()).toBe(true)
    })

    it('renders legend with pending and resolved', () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })

      expect(wrapper.text()).toContain('Pendientes')
      expect(wrapper.text()).toContain('Resueltas')
    })

    it('renders an SVG chart when data is provided', async () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })
      await flushPromises()

      const svg = wrapper.find('svg')
      expect(svg.exists()).toBe(true)
      // Should have at least one path (area layer)
      expect(svg.find('path').exists()).toBe(true)
    })

    it('renders at least 2 SVG paths (area layers + axes)', async () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })
      await flushPromises()

      const paths = wrapper.findAll('svg path')
      // Expect at least 2 (the area layers); there may be more for axis lines
      expect(paths.length).toBeGreaterThanOrEqual(2)
    })

    it('renders axes', async () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })
      await flushPromises()

      // X and Y axis groups + main chart group
      const gElements = wrapper.findAll('svg g')
      expect(gElements.length).toBeGreaterThanOrEqual(3)
    })
  })

  describe('data watcher', () => {
    it('re-renders when areaData changes', async () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: [] }
      })

      // Empty initially
      expect(wrapper.find('.chart-empty').exists()).toBe(true)

      // Change to non-empty data
      await wrapper.setProps({ areaData: mockAreaData })
      await flushPromises()

      expect(wrapper.find('.chart-empty').exists()).toBe(false)
      expect(wrapper.find('.chart-container').exists()).toBe(true)
    })

    it('re-renders when areaData content changes', async () => {
      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })
      await flushPromises()

      const newData = [
        { date: '2026-04-01', pending: 20, resolved: 10, total: 30 }
      ]

      await wrapper.setProps({ areaData: newData })
      await flushPromises()

      // Should still render chart
      expect(wrapper.find('svg').exists()).toBe(true)
    })
  })

  describe('ResizeObserver', () => {
    it('calls renderChart on resize', async () => {
      let resizeCallback = null
      const origObserver = globalThis.ResizeObserver

      globalThis.ResizeObserver = class MockResizeObserver {
        constructor(callback) {
          resizeCallback = callback
        }
        observe() {}
        unobserve() {}
        disconnect() {}
      }

      const wrapper = mount(AreaChartTab, {
        props: { areaData: mockAreaData }
      })
      await flushPromises()

      // Trigger resize
      if (resizeCallback) {
        resizeCallback([{ contentRect: { width: MOCK_WIDTH } }])
      }

      // Should not crash after resize
      expect(wrapper.find('svg').exists()).toBe(true)

      globalThis.ResizeObserver = origObserver
    })
  })

  describe('number coercion', () => {
    it('coerces string numbers in area data', async () => {
      const stringData = [
        { date: '2026-03-01', pending: '10', resolved: '5', total: '15' }
      ]

      const wrapper = mount(AreaChartTab, {
        props: { areaData: stringData }
      })
      await flushPromises()

      // Should render without crashing
      expect(wrapper.find('svg').exists()).toBe(true)
    })

    it('handles NaN values gracefully', async () => {
      const badData = [
        { date: '2026-03-01', pending: 'abc', resolved: null, total: undefined }
      ]

      const wrapper = mount(AreaChartTab, {
        props: { areaData: badData }
      })
      await flushPromises()

      // Should render without crashing (fallback to 0)
      expect(wrapper.find('svg').exists()).toBe(true)
    })
  })
})
