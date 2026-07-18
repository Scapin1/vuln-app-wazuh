import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GanttTab from '@/presentation/views/timeline/components/GanttTab.vue'

const mockRouterPush = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockRouterPush })
}))

// ── Helper: build mock CVEs with snapshot-shaped data ──
function makeCveSnapshots(overrides = {}) {
  return {
    cve_id: 'CVE-TEST-001',
    severity: 'HIGH',
    description: 'Test vulnerability',
    snapshots: [
      { syncTimestamp: '2026-06-01T10:00:00Z', agents: ['srv-a'], agentCount: 1 },
      { syncTimestamp: '2026-07-01T10:00:00Z', agents: ['srv-b'], agentCount: 1 },
    ],
    isResolved: false,
    firstSync: '2026-06-01T10:00:00Z',
    lastSync: '2026-07-01T10:00:00Z',
    ...overrides
  }
}

const MOCK_SNAPSHOTS = [
  {
    cve_id: 'CVE-2026-0001',
    severity: 'CRITICAL',
    description: 'RCE en modulo de autenticacion',
    snapshots: [
      { syncTimestamp: '2026-03-01T00:00:00Z', agents: ['srv-web-01', 'srv-db-02', 'srv-api-03'], agentCount: 3 },
      { syncTimestamp: '2026-04-01T00:00:00Z', agents: ['srv-web-01', 'srv-db-02'], agentCount: 2 },
      { syncTimestamp: '2026-05-01T00:00:00Z', agents: ['srv-web-01'], agentCount: 1 }
    ],
    firstSync: '2026-03-01T00:00:00Z',
    lastSync: '2026-05-01T00:00:00Z',
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0002',
    severity: 'HIGH',
    description: 'SQL Injection en API REST',
    snapshots: [
      { syncTimestamp: '2026-03-15T00:00:00Z', agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 },
      { syncTimestamp: '2026-04-15T00:00:00Z', agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 },
      { syncTimestamp: '2026-05-15T00:00:00Z', agents: ['srv-api-01', 'srv-web-02'], agentCount: 2 }
    ],
    firstSync: '2026-03-15T00:00:00Z',
    lastSync: '2026-05-15T00:00:00Z',
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0003',
    severity: 'MEDIUM',
    description: 'XSS reflejado en dashboard',
    snapshots: [
      { syncTimestamp: '2026-02-01T00:00:00Z', agents: ['srv-app-04'], agentCount: 1 },
      { syncTimestamp: '2026-03-01T00:00:00Z', agents: ['srv-app-04', 'srv-web-03'], agentCount: 2 },
      { syncTimestamp: '2026-04-01T00:00:00Z', agents: [], agentCount: 0 },
      { syncTimestamp: '2026-05-01T00:00:00Z', agents: ['srv-app-04', 'srv-web-03', 'srv-db-01'], agentCount: 3 }
    ],
    firstSync: '2026-02-01T00:00:00Z',
    lastSync: '2026-05-01T00:00:00Z',
    isResolved: false
  },
  {
    cve_id: 'CVE-2026-0004',
    severity: 'LOW',
    description: 'Info disclosure en header HTTP',
    snapshots: [
      { syncTimestamp: '2026-01-10T00:00:00Z', agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: '2026-02-10T00:00:00Z', agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: '2026-03-10T00:00:00Z', agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: '2026-04-10T00:00:00Z', agents: ['srv-proxy-05'], agentCount: 1 },
      { syncTimestamp: '2026-05-10T00:00:00Z', agents: [], agentCount: 0 }
    ],
    firstSync: '2026-01-10T00:00:00Z',
    lastSync: '2026-05-10T00:00:00Z',
    isResolved: true
  },
  {
    cve_id: 'CVE-2026-0005',
    severity: 'CRITICAL',
    description: 'Desbordamiento de buffer en servicio DHCP',
    snapshots: [
      { syncTimestamp: '2026-04-05T00:00:00Z', agents: ['srv-dhcp-01', 'srv-dhcp-02', 'srv-dhcp-03', 'srv-dhcp-04', 'srv-dhcp-05'], agentCount: 5 }
    ],
    firstSync: '2026-04-05T00:00:00Z',
    lastSync: '2026-04-05T00:00:00Z',
    isResolved: false
  }
]

describe('GanttTab.vue', () => {
  beforeEach(() => {
    mockRouterPush.mockClear()
  })

  describe('rendering with snapshots prop', () => {
    it('renders the gantt card and title', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      expect(wrapper.find('.gantt-card').exists()).toBe(true)
      expect(wrapper.text()).toContain('Seguimiento de CVEs')
    })

    it('renders CVE headers from snapshots', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.text()).toContain('CVE-2026-0002')
      expect(wrapper.text()).toContain('CVE-2026-0003')
      expect(wrapper.text()).toContain('CVE-2026-0004')
      expect(wrapper.text()).toContain('CVE-2026-0005')
    })

    it('renders severity badges', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      expect(wrapper.text()).toContain('CRITICAL')
      expect(wrapper.text()).toContain('HIGH')
      expect(wrapper.text()).toContain('MEDIUM')
      expect(wrapper.text()).toContain('LOW')
    })

    it('renders sync count info for each CVE', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      expect(wrapper.text()).toContain('sincronizaciones')
      // CVE-2026-0001 has 3 snapshots
      expect(wrapper.text()).toContain('3 sincronizaciones')
      // CVE-2026-0004 has 5 snapshots (including resolved)
      expect(wrapper.text()).toContain('5 sincronizaciones')
    })

    it('renders snapshot bar elements', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      const bars = wrapper.findAll('.gantt-bar')
      expect(bars.length).toBeGreaterThan(0)
    })

    it('renders different bar classes by status (detected / reopened / resolved)', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      const detectedBars = wrapper.findAll('.gantt-bar.snap-detected')
      const reopenedBars = wrapper.findAll('.gantt-bar.snap-reopened')
      const resolvedBars = wrapper.findAll('.gantt-bar.snap-resolved')

      // At least one of each type should exist in mock data
      expect(detectedBars.length).toBeGreaterThan(0)
      expect(reopenedBars.length).toBeGreaterThan(0)
      expect(resolvedBars.length).toBeGreaterThan(0)
    })

    it('renders updated legend items', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      expect(wrapper.text()).toContain('Activo')
      expect(wrapper.text()).toContain('Reabierto')
      expect(wrapper.text()).toContain('Resuelto')
    })

    it('renders zoom controls', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      const zoomBtns = wrapper.findAll('.zoom-btn')
      expect(zoomBtns.length).toBe(2)

      expect(wrapper.find('.zoom-level').exists()).toBe(true)
      expect(wrapper.find('.zoom-level').text()).toBe('Mes')
    })
  })

  describe('empty state', () => {
    it('shows empty state when snapshots is an empty array', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: [] }
      })

      expect(wrapper.find('.gantt-empty-state').exists()).toBe(true)
      expect(wrapper.text()).toContain('No hay datos de vulnerabilidades para mostrar')
      expect(wrapper.find('.gantt-body').exists()).toBe(false)
    })

    it('shows loading state when snapshots is null/undefined', () => {
      const wrapper = mount(GanttTab, {})
      expect(wrapper.find('.gantt-loading-state').exists()).toBe(true)
      expect(wrapper.text()).toContain('Cargando datos')
    })
  })

  describe('zoom controls', () => {
    it('starts at month zoom level', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.zoomIndex).toBe(1)
      expect(wrapper.vm.zoomLabel).toBe('Mes')
      expect(wrapper.vm.MONTH_WIDTH).toBe(100)
    })

    it('zoomIn increases zoom index', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.zoomIndex).toBe(1)

      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(2)
      expect(wrapper.vm.zoomLabel).toBe('Dia')
      expect(wrapper.vm.MONTH_WIDTH).toBe(50)
    })

    it('zoomOut decreases zoom index', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(2)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(1)
    })

    it('does not zoom out below minimum', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
      expect(wrapper.vm.zoomLabel).toBe('Año')
      expect(wrapper.vm.MONTH_WIDTH).toBe(80)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
    })

    it('does not zoom in above maximum', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      for (let i = 0; i < 3; i++) {
        await wrapper.find('.zoom-btn:last-child').trigger('click')
      }
      expect(wrapper.vm.zoomIndex).toBe(3)
      expect(wrapper.vm.zoomLabel).toBe('Hora')
      expect(wrapper.vm.MONTH_WIDTH).toBe(40)

      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(3)
    })

    it('changes time labels when zooming', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })

      const monthText = wrapper.find('.month-label').text()
      expect(monthText.length).toBeGreaterThan(0)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      const yearText = wrapper.find('.month-label').text()
      expect(yearText).toMatch(/^\d{4}$/)
    })
  })

  describe('pagination', () => {
    it('hides pagination when totalPages prop is 1', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, currentPage: 1, totalPages: 1 }
      })
      expect(wrapper.find('.gantt-pagination').exists()).toBe(false)
    })

    it('shows pagination when totalPages prop > 1', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, currentPage: 1, totalPages: 3 }
      })
      expect(wrapper.find('.gantt-pagination').exists()).toBe(true)
      expect(wrapper.find('.page-info').text()).toContain('Pagina 1 de 3')
    })

    it('disables Previous on first page', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, currentPage: 1, totalPages: 3 }
      })
      const pageBtns = wrapper.findAll('.page-btn')
      expect(pageBtns[0].element.disabled).toBe(true)
      expect(pageBtns[1].element.disabled).toBe(false)
    })

    it('disables Siguiente on last page', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, currentPage: 3, totalPages: 3 }
      })
      const pageBtns = wrapper.findAll('.page-btn')
      expect(pageBtns[0].element.disabled).toBe(false)
      expect(pageBtns[1].element.disabled).toBe(true)
    })
  })

  describe('toLocalDate helper', () => {
    it('handles null/undefined input', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const result = wrapper.vm.toLocalDate(null)
      expect(result).toBeInstanceOf(Date)
    })

    it('handles Date object input', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const now = new Date('2026-05-15T10:30:00Z')
      const result = wrapper.vm.toLocalDate(now)
      expect(result).toBeInstanceOf(Date)
      expect(result.getTime()).toBe(now.getTime())
    })

    it('handles ISO date string with time', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const result = wrapper.vm.toLocalDate('2026-03-15T14:30:00Z')
      expect(result).toBeInstanceOf(Date)
      expect(result.getTime()).toBe(new Date('2026-03-15T14:30:00Z').getTime())
    })

    it('handles ISO date string without time', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const result = wrapper.vm.toLocalDate('2026-03-15')
      expect(result).toBeInstanceOf(Date)
    })
  })

  describe('formatDate helper', () => {
    it('returns dash for null input', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.formatDate(null)).toBe('-')
    })

    it('formats date string correctly', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const result = wrapper.vm.formatDate('2026-03-15')
      expect(result).toContain('2026')
    })
  })

  describe('getSnapshotBarStyle helper', () => {
    it('returns left and width properties', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = wrapper.vm.cveSnapshots[0]
      if (cve && cve.snapshots.length > 0) {
        const style = wrapper.vm.getSnapshotBarStyle(cve, 0)
        expect(style).toHaveProperty('left')
        expect(style).toHaveProperty('width')
      }
    })
  })

  describe('timeLabels computed', () => {
    it('returns non-empty labels with snapshots data', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.timeLabels.length).toBeGreaterThan(0)

      wrapper.vm.timeLabels.forEach(label => {
        expect(label).toHaveProperty('label')
        expect(label).toHaveProperty('date')
        expect(typeof label.label).toBe('string')
        expect(label.date).toBeInstanceOf(Date)
      })
    })

    it('generates year labels at year zoom', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      await wrapper.find('.zoom-btn:first-child').trigger('click')

      expect(wrapper.vm.zoomLabel).toBe('Año')
      wrapper.vm.timeLabels.forEach(label => {
        expect(label.label).toMatch(/^\d{4}$/)
      })
    })

    it('generates day labels at day zoom', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      await wrapper.find('.zoom-btn:last-child').trigger('click')

      expect(wrapper.vm.zoomLabel).toBe('Dia')
      wrapper.vm.timeLabels.forEach(label => {
        expect(label.label.length).toBeGreaterThan(0)
      })
    })
  })

  describe('msPerUnit computed', () => {
    it('returns correct ms for year unit', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.zoomIndex = 0
      expect(wrapper.vm.msPerUnit).toBeCloseTo(365.25 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for month unit', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.zoomIndex = 1
      expect(wrapper.vm.msPerUnit).toBeCloseTo(30.44 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for day unit', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.zoomIndex = 2
      expect(wrapper.vm.msPerUnit).toBe(24 * 60 * 60 * 1000)
    })

    it('returns correct ms for hour unit', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.zoomIndex = 3
      expect(wrapper.vm.msPerUnit).toBe(60 * 60 * 1000)
    })
  })

  describe('cveSnapshots computed', () => {
    it('returns snapshots as-is from the prop with zoom merging applied', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const snapshots = wrapper.vm.cveSnapshots
      expect(snapshots.length).toBe(5)
    })

    it('each CVE snapshot has correct shape', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const snapshots = wrapper.vm.cveSnapshots

      snapshots.forEach(cve => {
        expect(cve).toHaveProperty('cve_id')
        expect(cve).toHaveProperty('severity')
        expect(cve).toHaveProperty('description')
        expect(cve).toHaveProperty('snapshots')
        expect(Array.isArray(cve.snapshots)).toBe(true)
        expect(cve).toHaveProperty('isResolved')
        expect(typeof cve.isResolved).toBe('boolean')

        cve.snapshots.forEach(snap => {
          expect(snap).toHaveProperty('syncTimestamp')
          expect(snap).toHaveProperty('agents')
          expect(Array.isArray(snap.agents)).toBe(true)
          expect(snap).toHaveProperty('agentCount')
          expect(typeof snap.agentCount).toBe('number')
        })
      })
    })

    it('marks CVE-2026-0004 as resolved (last snapshot has 0 agents)', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = wrapper.vm.cveSnapshots.find(c => c.cve_id === 'CVE-2026-0004')
      expect(cve.cve_id).toBe('CVE-2026-0004')
      expect(cve.isResolved).toBe(true)
      const lastSnap = cve.snapshots[cve.snapshots.length - 1]
      expect(lastSnap.agentCount).toBe(0)
    })

    it('applies mergeSnapshotsByZoom to each CVE snapshots', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const snapshots = wrapper.vm.cveSnapshots
      snapshots.forEach(cve => {
        expect(Array.isArray(cve.snapshots)).toBe(true)
      })
    })
  })

  describe('mergeSnapshotsByZoom', () => {
    it('merges snapshots within daily threshold at month zoom', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: [] }
      })
      // Set zoom to 'Mes' (index 1)
      wrapper.vm.zoomIndex = 1

      const snapshots = [
        { syncTimestamp: '2026-06-01T10:00:00Z', agents: ['srv-a'], agentCount: 1 },
        { syncTimestamp: '2026-06-01T10:05:00Z', agents: ['srv-b'], agentCount: 1 },
        { syncTimestamp: '2026-06-15T00:00:00Z', agents: ['srv-c'], agentCount: 1 },
      ]

      const merged = wrapper.vm.mergeSnapshotsByZoom(snapshots)
      // First 2 (same day) merged, 3rd stays separate
      expect(merged.length).toBe(2)
      expect(merged[0].agents).toContain('srv-a')
      expect(merged[0].agents).toContain('srv-b')
      expect(merged[0].agentCount).toBe(2)
      expect(merged[1].agents).toContain('srv-c')
    })

    it('keeps distant timestamps separate', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: [] }
      })
      wrapper.vm.zoomIndex = 1

      const snapshots = [
        { syncTimestamp: '2026-01-01T00:00:00Z', agents: ['srv-a'], agentCount: 1 },
        { syncTimestamp: '2026-06-01T00:00:00Z', agents: ['srv-b'], agentCount: 1 },
      ]

      expect(wrapper.vm.mergeSnapshotsByZoom(snapshots).length).toBe(2)
    })
  })

  describe('scrollToDate', () => {
    it('handles empty searchDate gracefully', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })

    it('handles missing scrollTo method gracefully', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.searchDate = '2026-04-01T00:00'

      if (wrapper.vm.scrollWrapper && typeof wrapper.vm.scrollWrapper.scrollTo !== 'function') {
        wrapper.vm.scrollWrapper.scrollTo = vi.fn()
      }

      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })
  })

  describe('page-change emit', () => {
    it('emits page-change when goToPage is called', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, currentPage: 1, totalPages: 3 }
      })
      wrapper.vm.goToPage(2)
      expect(wrapper.emitted('page-change')).toBeTruthy()
      expect(wrapper.emitted('page-change')[0]).toEqual([2])
    })
  })

  describe('totalPages prop', () => {
    it('uses totalPages from prop', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS, totalPages: 3 }
      })
      expect(wrapper.vm.totalPages).toBe(3)
    })

    it('defaults to 1 when totalPages is not provided', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.totalPages).toBe(1)
    })
  })

  describe('Tooltip interactions', () => {
    it('initial tooltip state is hidden', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      expect(wrapper.vm.isHovering).toBe(false)
      expect(wrapper.vm.hoveredSnapshot).toBe(null)
      expect(wrapper.find('.gantt-tooltip').exists()).toBe(false)
    })

    it('handleBarMouseEnter sets hover state', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = wrapper.vm.cveSnapshots[0]
      const snap = cve.snapshots[0]
      const event = { clientX: 100, clientY: 200 }

      wrapper.vm.handleBarMouseEnter(snap, cve, event)

      expect(wrapper.vm.isHovering).toBe(true)
      expect(wrapper.vm.hoveredSnapshot).not.toBeNull()
      expect(wrapper.vm.hoveredSnapshot.cve_id).toBe(cve.cve_id)
      expect(wrapper.vm.hoveredSnapshot.syncTimestamp).toBe(snap.syncTimestamp)
      expect(wrapper.vm.tooltipPos.x).toBe(112) // clientX + 12
      expect(wrapper.vm.tooltipPos.y).toBe(190) // clientY - 10
    })

    it('handleBarMouseLeave clears hover state after delay', async () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = wrapper.vm.cveSnapshots[0]
      const snap = cve.snapshots[0]

      wrapper.vm.handleBarMouseEnter(snap, cve, { clientX: 100, clientY: 200 })
      expect(wrapper.vm.isHovering).toBe(true)

      wrapper.vm.handleBarMouseLeave()
      // State persists during the 100ms delay
      expect(wrapper.vm.isHovering).toBe(true)
      expect(wrapper.vm.hoveredSnapshot).not.toBeNull()

      // After delay, it clears
      await new Promise(r => setTimeout(r, 150))
      expect(wrapper.vm.isHovering).toBe(false)
      expect(wrapper.vm.hoveredSnapshot).toBe(null)
    })

    it('handleBarMouseMove updates tooltip position', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.isHovering = true

      wrapper.vm.handleBarMouseMove({ clientX: 300, clientY: 150 })
      expect(wrapper.vm.tooltipPos.x).toBe(312)
      expect(wrapper.vm.tooltipPos.y).toBe(140)
    })
  })

  describe('getSnapshotBarClass (status-based)', () => {
    const makeCve = (snapshots) => ({ snapshots })

    it('returns snap-resolved when agentCount is 0', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 0 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 0)).toBe('snap-resolved')
    })

    it('returns snap-detected when first snapshot has agents', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 2 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 0)).toBe('snap-detected')
    })

    it('returns snap-detected when agentCount > 0 and previous was also > 0', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 1 }, { agentCount: 3 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 1)).toBe('snap-detected')
    })

    it('returns snap-reopened when previous snapshot had 0 agents', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 0 }, { agentCount: 2 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 1)).toBe('snap-reopened')
    })
  })

  describe('getSnapshotStatusLabel', () => {
    const makeCve = (snapshots) => ({ snapshots })

    it('returns Resuelto for 0 agents', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 0 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 0)).toBe('Resuelto')
    })

    it('returns Activo for first snapshot with agents', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 1 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 0)).toBe('Activo')
    })

    it('returns Reabierto when previous snapshot had 0 agents', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = makeCve([{ agentCount: 0 }, { agentCount: 3 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 1)).toBe('Reabierto')
    })
  })

  describe('CSS cleanup — title label style', () => {
    it('uses CSS class instead of inline style on searchDate label', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const label = wrapper.find('label[for="ganttSearchDate"]')
      expect(label.exists()).toBe(true)
      expect(label.attributes('style')).toBeUndefined()
    })
  })

  describe('Date picker and search', () => {
    it('onGanttDatePickerChange sets searchDate from Date object', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.onGanttDatePickerChange(new Date('2026-07-15T14:30:00'))
      expect(wrapper.vm.searchDate).toBe('2026-07-15T14:30')
    })

    it('onGanttDatePickerChange ignores null date', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.onGanttDatePickerChange(null)
      expect(wrapper.vm.searchDate).toBe('')
    })
  })

  describe('Bar click navigation', () => {
    it('handleBarClick navigates to timeline with query params', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = {
        cve_id: 'CVE-TEST',
        snapshots: [
          { syncTimestamp: '2026-07-01T10:00:00Z', agents: ['agent-1', 'agent-2'] },
          { syncTimestamp: '2026-07-10T10:00:00Z' }
        ]
      }
      wrapper.vm.handleBarClick(cve, 0)
      expect(mockRouterPush).toHaveBeenCalledWith({
        path: '/timeline',
        query: { cve: 'CVE-TEST', agents: 'agent-1,agent-2', syncStart: '2026-07-01T10:00:00Z', syncEnd: '2026-07-10T10:00:00Z' }
      })
    })

    it('handleBarClick with no agents uses empty string', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = {
        cve_id: 'CVE-NOAGENTS',
        snapshots: [{ syncTimestamp: '2026-07-01T10:00:00Z' }]
      }
      wrapper.vm.handleBarClick(cve, 0)
      expect(mockRouterPush).toHaveBeenCalledWith({
        path: '/timeline',
        query: { cve: 'CVE-NOAGENTS', agents: '', syncStart: '2026-07-01T10:00:00Z', syncEnd: expect.any(String) }
      })
    })
  })

  describe('Tooltip edge cases', () => {
    it('cancelLeaveTimeout clears the leave timeout', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.startLeaveTimeout()
      expect(wrapper.vm.leaveTimeout).not.toBeNull()
      wrapper.vm.cancelLeaveTimeout()
      expect(wrapper.vm.leaveTimeout).toBeNull()
    })

    it('handleBarMouseEnter clears existing leaveTimeout', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      const cve = wrapper.vm.cveSnapshots[0]
      const snap = cve.snapshots[0]

      // Start a leave timeout first
      wrapper.vm.startLeaveTimeout()
      expect(wrapper.vm.leaveTimeout).not.toBeNull()

      // Enter again — should clear the old timeout
      wrapper.vm.handleBarMouseEnter(snap, cve, { clientX: 100, clientY: 200 })
      expect(wrapper.vm.isHovering).toBe(true)
      expect(wrapper.vm.leaveTimeout).toBeNull()
    })

    it('refineTooltipPos flips tooltip when near viewport edges', () => {
      const wrapper = mount(GanttTab, {
        props: { snapshots: MOCK_SNAPSHOTS }
      })
      wrapper.vm.isHovering = true
      wrapper.vm.hoveredSnapshot = { cve_id: 'CVE-TEST', syncTimestamp: '2026-07-01T10:00:00Z', agents: [] }
      wrapper.vm.tooltipRef = { offsetHeight: 100, offsetWidth: 200 }

      // Near bottom edge — should flip above cursor
      const nearBottom = { clientX: 100, clientY: window.innerHeight - 5 }
      wrapper.vm.refineTooltipPos(nearBottom)
      // y becomes clientY - tooltipHeight - 12 = (innerH - 5) - 100 - 12
      expect(wrapper.vm.tooltipPos.y).toBe(window.innerHeight - 117)

      // Near right edge — should flip left
      const nearRight = { clientX: window.innerWidth - 10, clientY: 100 }
      wrapper.vm.refineTooltipPos(nearRight)
      // x becomes clientX - tooltipWidth - 12 = (innerW - 10) - 200 - 12
      expect(wrapper.vm.tooltipPos.x).toBe(window.innerWidth - 222)
    })
  })

  describe('Pagination', () => {
    const manyCves = Array.from({ length: 25 }, (_, i) => ({
      cve_id: `CVE-PAG-${String(i + 1).padStart(4, '0')}`,
      severity: 'HIGH',
      description: `Pagination CVE ${i + 1}`,
      snapshots: [{ syncTimestamp: '2026-07-01T10:00:00Z', agentCount: 1 }]
    }))

    it('shows pagination when totalPages prop > 1', () => {
      const wrapper = mount(GanttTab, { props: { snapshots: manyCves, currentPage: 1, totalPages: 2 } })
      expect(wrapper.find('.gantt-pagination').exists()).toBe(true)
    })

    it('clicking Siguiente emits page-change with next page', async () => {
      const wrapper = mount(GanttTab, { props: { snapshots: manyCves, currentPage: 1, totalPages: 2 } })
      expect(wrapper.find('.page-btn:last-child').element.disabled).toBe(false)

      await wrapper.find('.page-btn:last-child').trigger('click')
      expect(wrapper.emitted('page-change')).toBeTruthy()
      expect(wrapper.emitted('page-change')[0]).toEqual([2])
    })

    it('clicking Anterior emits page-change with prev page', async () => {
      const wrapper = mount(GanttTab, { props: { snapshots: manyCves, currentPage: 2, totalPages: 2 } })
      await wrapper.vm.$nextTick()

      const btns = wrapper.findAll('.page-btn')
      await btns[0].trigger('click')
      expect(wrapper.emitted('page-change')).toBeTruthy()
      expect(wrapper.emitted('page-change')[0]).toEqual([1])
    })

    it('Anterior button is disabled on page 1', () => {
      const wrapper = mount(GanttTab, { props: { snapshots: manyCves, currentPage: 1, totalPages: 2 } })
      const btns = wrapper.findAll('.page-btn')
      expect(btns[0].element.disabled).toBe(true)
    })

    it('Siguiente button is disabled on last page', () => {
      const wrapper = mount(GanttTab, { props: { snapshots: manyCves, currentPage: 2, totalPages: 2 } })
      const btns = wrapper.findAll('.page-btn')
      expect(btns[1].element.disabled).toBe(true)
    })

    it('bar click calls handleBarClick via template event', async () => {
      const wrapper = mount(GanttTab, { props: { snapshots: MOCK_SNAPSHOTS, currentPage: 1, totalPages: 1 } })
      const firstBar = wrapper.find('.gantt-bar')
      expect(firstBar.exists()).toBe(true)
      await firstBar.trigger('click')
      expect(mockRouterPush).toHaveBeenCalled()
    })
  })

  describe('zoom edge cases', () => {
    it('zoom at max level does not increment further', async () => {
      const wrapper = mount(GanttTab, { props: { snapshots: MOCK_SNAPSHOTS } })
      // Start at Mes (index 1), go to Hora (index 3)
      for (let i = 0; i < 3; i++) {
        await wrapper.find('.zoom-btn:last-child').trigger('click')
      }
      expect(wrapper.vm.zoomIndex).toBe(3)
      expect(wrapper.vm.zoomLabel).toBe('Hora')
      // One more click should stay at 3
      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(3)
      // At hour zoom, msPerUnit should be 3600000
      expect(wrapper.vm.msPerUnit).toBe(60 * 60 * 1000)
    })

    it('zoom at min level does not decrement further', async () => {
      const wrapper = mount(GanttTab, { props: { snapshots: MOCK_SNAPSHOTS } })
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
      expect(wrapper.vm.zoomLabel).toBe('Año')
      // One more click should stay at 0
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
      // At year zoom, msPerUnit should be year ms
      expect(wrapper.vm.msPerUnit).toBeCloseTo(365.25 * 24 * 60 * 60 * 1000, 0)
    })
  })
})
