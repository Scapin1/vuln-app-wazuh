import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GanttTab from '@/presentation/views/timeline/components/GanttTab.vue'

const mockRouterPush = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockRouterPush })
}))

describe('GanttTab.vue', () => {
  beforeEach(() => {
    mockRouterPush.mockClear()
  })

  // With empty ganttData, DEMO_SNAPSHOTS is shown (5 CVEs)
  const emptyWrapper = () => mount(GanttTab, {
    props: { ganttData: [] }
  })

  describe('rendering with DEMO data only', () => {
    it('renders the gantt card and title', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.find('.gantt-card').exists()).toBe(true)
      expect(wrapper.text()).toContain('Seguimiento de CVEs')
    })

    it('renders CVE headers from DEMO_SNAPSHOTS', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.text()).toContain('CVE-2026-0002')
      expect(wrapper.text()).toContain('CVE-2026-0003')
      expect(wrapper.text()).toContain('CVE-2026-0004')
      expect(wrapper.text()).toContain('CVE-2026-0005')
    })

    it('renders severity badges', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('CRITICAL')
      expect(wrapper.text()).toContain('HIGH')
      expect(wrapper.text()).toContain('MEDIUM')
      expect(wrapper.text()).toContain('LOW')
    })

    it('renders sync count info for each CVE', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('sincronizaciones')
      // CVE-2026-0001 has 3 snapshots
      expect(wrapper.text()).toContain('3 sincronizaciones')
      // CVE-2026-0004 has 5 snapshots (including resolved)
      expect(wrapper.text()).toContain('5 sincronizaciones')
    })

    it('renders snapshot bar elements', () => {
      const wrapper = emptyWrapper()

      const bars = wrapper.findAll('.gantt-bar')
      expect(bars.length).toBeGreaterThan(0)
    })

    it('renders different bar classes by status (detected / reopened / resolved)', () => {
      const wrapper = emptyWrapper()

      const detectedBars = wrapper.findAll('.gantt-bar.snap-detected')
      const reopenedBars = wrapper.findAll('.gantt-bar.snap-reopened')
      const resolvedBars = wrapper.findAll('.gantt-bar.snap-resolved')

      // At least one of each type should exist in DEMO data
      expect(detectedBars.length).toBeGreaterThan(0)
      expect(reopenedBars.length).toBeGreaterThan(0)
      expect(resolvedBars.length).toBeGreaterThan(0)
    })

    it('renders updated legend items', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('Activo')
      expect(wrapper.text()).toContain('Reabierto')
      expect(wrapper.text()).toContain('Resuelto')
    })

    it('renders zoom controls', () => {
      const wrapper = emptyWrapper()

      const zoomBtns = wrapper.findAll('.zoom-btn')
      expect(zoomBtns.length).toBe(2)

      expect(wrapper.find('.zoom-level').exists()).toBe(true)
      expect(wrapper.find('.zoom-level').text()).toBe('Mes')
    })
  })

  describe('zoom controls', () => {
    it('starts at month zoom level', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.zoomIndex).toBe(1)
      expect(wrapper.vm.zoomLabel).toBe('Mes')
      expect(wrapper.vm.MONTH_WIDTH).toBe(100)
    })

    it('zoomIn increases zoom index', async () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.zoomIndex).toBe(1)

      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(2)
      expect(wrapper.vm.zoomLabel).toBe('Dia')
      expect(wrapper.vm.MONTH_WIDTH).toBe(50)
    })

    it('zoomOut decreases zoom index', async () => {
      const wrapper = emptyWrapper()
      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(2)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(1)
    })

    it('does not zoom out below minimum', async () => {
      const wrapper = emptyWrapper()
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
      expect(wrapper.vm.zoomLabel).toBe('Año')
      expect(wrapper.vm.MONTH_WIDTH).toBe(80)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
    })

    it('does not zoom in above maximum', async () => {
      const wrapper = emptyWrapper()
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
      const wrapper = emptyWrapper()

      const monthText = wrapper.find('.month-label').text()
      expect(monthText.length).toBeGreaterThan(0)

      await wrapper.find('.zoom-btn:first-child').trigger('click')
      const yearText = wrapper.find('.month-label').text()
      expect(yearText).toMatch(/^\d{4}$/)
    })
  })

  describe('pagination', () => {
    it('shows pagination when DEMO data exceeds ITEMS_PER_PAGE', () => {
      const wrapper = emptyWrapper()

      const totalPages = wrapper.vm.totalPages
      if (totalPages > 1) {
        expect(wrapper.find('.gantt-pagination').exists()).toBe(true)
        expect(wrapper.find('.page-info').text()).toContain(`Pagina 1 de ${totalPages}`)
      }
    })

    it('navigates pages when clicking Next', async () => {
      const wrapper = emptyWrapper()

      if (wrapper.vm.totalPages > 1) {
        const nextBtn = wrapper.find('.page-btn:last-child')
        expect(nextBtn.exists()).toBe(true)
        expect(nextBtn.element.disabled).toBe(false)

        await nextBtn.trigger('click')
        expect(wrapper.vm.currentPage).toBe(2)
        expect(wrapper.find('.page-info').text()).toContain('Pagina 2')
      }
    })

    it('disables Previous on first page', () => {
      const wrapper = emptyWrapper()

      if (wrapper.vm.totalPages > 1) {
        const pageBtns = wrapper.findAll('.page-btn')
        const prevBtn = pageBtns.at(0)
        expect(prevBtn.exists()).toBe(true)
        expect(prevBtn.element.disabled).toBe(true)
      }
    })
  })

  describe('toLocalDate helper', () => {
    it('handles null/undefined input', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.toLocalDate(null)
      expect(result).toBeInstanceOf(Date)
    })

    it('handles Date object input', () => {
      const wrapper = emptyWrapper()
      const now = new Date('2026-05-15T10:30:00Z')
      const result = wrapper.vm.toLocalDate(now)
      expect(result).toBeInstanceOf(Date)
      expect(result.getTime()).toBe(now.getTime())
    })

    it('handles ISO date string with time', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.toLocalDate('2026-03-15T14:30:00Z')
      expect(result).toBeInstanceOf(Date)
      // parseServerDate correctly converts UTC string to Date object
      // getTime() is timezone-independent, so we compare absolute timestamps
      expect(result.getTime()).toBe(new Date('2026-03-15T14:30:00Z').getTime())
    })

    it('handles ISO date string without time', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.toLocalDate('2026-03-15')
      expect(result).toBeInstanceOf(Date)
    })
  })

  describe('formatDate helper', () => {
    it('returns dash for null input', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.formatDate(null)).toBe('-')
    })

    it('formats date string correctly', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.formatDate('2026-03-15')
      expect(result).toContain('2026')
    })
  })

  describe('getSnapshotBarStyle helper', () => {
    it('returns empty object when no time labels', () => {
      const wrapper = emptyWrapper()
      // Mount with no data and force empty state to test guard
      // Use a minimal CVE with a snapshot to test positioning
      const cve = wrapper.vm.cveSnapshots[0]
      if (cve && cve.snapshots.length > 0) {
        const style = wrapper.vm.getSnapshotBarStyle(cve, 0)
        expect(style).toHaveProperty('left')
        expect(style).toHaveProperty('width')
      }
    })
  })

  describe('timeLabels computed', () => {
    it('returns non-empty labels with DEMO data', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.timeLabels.length).toBeGreaterThan(0)

      wrapper.vm.timeLabels.forEach(label => {
        expect(label).toHaveProperty('label')
        expect(label).toHaveProperty('date')
        expect(typeof label.label).toBe('string')
        expect(label.date).toBeInstanceOf(Date)
      })
    })

    it('generates year labels at year zoom', async () => {
      const wrapper = emptyWrapper()
      await wrapper.find('.zoom-btn:first-child').trigger('click')

      expect(wrapper.vm.zoomLabel).toBe('Año')
      wrapper.vm.timeLabels.forEach(label => {
        expect(label.label).toMatch(/^\d{4}$/)
      })
    })

    it('generates day labels at day zoom', async () => {
      const wrapper = emptyWrapper()
      await wrapper.find('.zoom-btn:last-child').trigger('click')

      expect(wrapper.vm.zoomLabel).toBe('Dia')
      wrapper.vm.timeLabels.forEach(label => {
        expect(label.label.length).toBeGreaterThan(0)
      })
    })
  })

  describe('msPerUnit computed', () => {
    it('returns correct ms for year unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 0
      expect(wrapper.vm.msPerUnit).toBeCloseTo(365.25 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for month unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 1
      expect(wrapper.vm.msPerUnit).toBeCloseTo(30.44 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for day unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 2
      expect(wrapper.vm.msPerUnit).toBe(24 * 60 * 60 * 1000)
    })

    it('returns correct ms for hour unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 3
      expect(wrapper.vm.msPerUnit).toBe(60 * 60 * 1000)
    })
  })

  describe('cveSnapshots computed', () => {
    it('uses DEMO data when ganttData is empty', () => {
      const wrapper = emptyWrapper()
      const snapshots = wrapper.vm.cveSnapshots

      expect(snapshots.length).toBe(5) // 5 DEMO CVEs
    })

    it('each CVE snapshot has correct shape', () => {
      const wrapper = emptyWrapper()
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
      const wrapper = emptyWrapper()
      const cve = wrapper.vm.cveSnapshots.find(c => c.cve_id === 'CVE-2026-0004')
      expect(cve.cve_id).toBe('CVE-2026-0004')
      expect(cve.isResolved).toBe(true)
      const lastSnap = cve.snapshots[cve.snapshots.length - 1]
      expect(lastSnap.agentCount).toBe(0)
    })

    it('parses real ganttData into CVE snapshots', () => {
      const realData = [
        {
          cve_id: 'CVE-REAL-001',
          severity: 'HIGH',
          description: 'Real vuln',
          agent_name: 'srv-web-01',
          agent_id: 'a1',
          first_seen: '2026-01-01T00:00:00Z',
          historySorted: [
            { action: 'RESOLVED', timestamp: '2026-03-01T00:00:00Z' }
          ]
        }
      ]
      const wrapper = mount(GanttTab, {
        props: { ganttData: realData }
      })

      expect(wrapper.text()).toContain('CVE-REAL-001')
      expect(wrapper.text()).not.toContain('DEMO')
      expect(wrapper.text()).toContain('HIGH')

      const snapshots = wrapper.vm.cveSnapshots
      expect(snapshots.length).toBe(1)
      expect(snapshots[0].snapshots).toHaveLength(1) // only history timestamps (Gantt uses syncs, not first_seen)
    })

    it('builds snapshots with real data correctly', () => {
      const realData = [
        {
          cve_id: 'CVE-MULTI',
          severity: 'MEDIUM',
          description: 'Multi agent test',
          agent_name: 'agent-01',
          agent_id: 'a1',
          first_seen: '2026-02-01T00:00:00Z',
          historySorted: [
            { action: 'RESOLVED', timestamp: '2026-04-01T00:00:00Z' }
          ]
        },
        {
          cve_id: 'CVE-MULTI',
          severity: 'MEDIUM',
          description: 'Multi agent test',
          agent_name: 'agent-02',
          agent_id: 'a2',
          first_seen: '2026-03-01T00:00:00Z',
          historySorted: []
        }
      ]
      const wrapper = mount(GanttTab, {
        props: { ganttData: realData }
      })

      const cve = wrapper.vm.cveSnapshots.find(c => c.cve_id === 'CVE-MULTI')
      expect(cve.cve_id).toBe('CVE-MULTI')
      // Only 1 timestamp: Apr 1 (agent-01 history RESOLVED)
      // first_seen is excluded — Gantt is driven by syncs, not first detection
      expect(cve.snapshots).toHaveLength(1)

      const snapTimestamps = cve.snapshots.map(s => s.syncTimestamp)
      expect(snapTimestamps.some(ts => ts.includes('2026-04-01'))).toBe(true)
      expect(snapTimestamps.some(ts => ts.includes('2026-02-01'))).toBe(false)
      expect(snapTimestamps.some(ts => ts.includes('2026-03-01'))).toBe(false)
    })

    it('groups agents by shared last_seen (sync) timestamp', () => {
      const realData = [
        {
          cve_id: 'CVE-SHARED-SYNC',
          severity: 'HIGH',
          description: 'Same CVE on multiple machines at same sync',
          agent_name: 'server-a',
          agent_id: 'a1',
          first_seen: '2026-01-15T00:00:00Z',
          last_seen: '2026-06-01T12:00:00Z',
          historySorted: []
        },
        {
          cve_id: 'CVE-SHARED-SYNC',
          severity: 'HIGH',
          description: 'Same CVE on multiple machines at same sync',
          agent_name: 'server-b',
          agent_id: 'a2',
          first_seen: '2026-02-10T00:00:00Z',
          last_seen: '2026-06-01T12:00:00Z',
          historySorted: []
        },
        {
          cve_id: 'CVE-SHARED-SYNC',
          severity: 'HIGH',
          description: 'Same CVE on multiple machines at same sync',
          agent_name: 'server-c',
          agent_id: 'a3',
          first_seen: '2026-03-05T00:00:00Z',
          last_seen: '2026-06-01T12:00:00Z',
          historySorted: []
        }
      ]
      const wrapper = mount(GanttTab, {
        props: { ganttData: realData }
      })

      const cve = wrapper.vm.cveSnapshots.find(c => c.cve_id === 'CVE-SHARED-SYNC')
      expect(cve.cve_id).toBe('CVE-SHARED-SYNC')

      // 1 snapshot: only the shared sync last_seen (first_seen excluded from Gantt)
      expect(cve.snapshots).toHaveLength(1)

      // The shared sync snapshot has all 3 agents
      const syncSnap = cve.snapshots.find(s => s.syncTimestamp.includes('2026-06-01'))
      expect(syncSnap.syncTimestamp).toContain('2026-06-01')
      expect(syncSnap.agentCount).toBe(3)
      expect(syncSnap.agents).toContain('server-a')
      expect(syncSnap.agents).toContain('server-b')
      expect(syncSnap.agents).toContain('server-c')
    })
  })

  describe('mergeSnapshotsByZoom', () => {
    it('merges snapshots within daily threshold at month zoom', () => {
      const wrapper = mount(GanttTab, {
        props: { ganttData: [] }
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
        props: { ganttData: [] }
      })
      wrapper.vm.zoomIndex = 1

      const snapshots = [
        { syncTimestamp: '2026-01-01T00:00:00Z', agents: ['srv-a'], agentCount: 1 },
        { syncTimestamp: '2026-06-01T00:00:00Z', agents: ['srv-b'], agentCount: 1 },
      ]

      expect(wrapper.vm.mergeSnapshotsByZoom(snapshots).length).toBe(2)
    })
  })

  describe('paginatedCveSnapshots', () => {
    it('returns correct page slice', () => {
      const wrapper = emptyWrapper()
      const page1 = wrapper.vm.paginatedCveSnapshots

      expect(page1.length).toBeLessThanOrEqual(20)
      expect(page1[0]).toHaveProperty('cve_id')
    })
  })

  describe('scrollToDate', () => {
    it('handles empty searchDate gracefully', () => {
      const wrapper = emptyWrapper()
      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })

    it('handles missing scrollTo method gracefully', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.searchDate = '2026-04-01T00:00'

      if (wrapper.vm.scrollWrapper && typeof wrapper.vm.scrollWrapper.scrollTo !== 'function') {
        wrapper.vm.scrollWrapper.scrollTo = vi.fn()
      }

      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })
  })

  describe('watch ganttData', () => {
    it('resets currentPage to 1 when ganttData changes', async () => {
      const wrapper = emptyWrapper()

      if (wrapper.vm.totalPages > 1) {
        wrapper.vm.currentPage = 2
        expect(wrapper.vm.currentPage).toBe(2)

        await wrapper.setProps({
          ganttData: [{
            cve_id: 'CVE-NEW',
            severity: 'HIGH',
            description: 'Test',
            agent_name: 'test',
            agent_id: 't1',
            first_seen: new Date().toISOString(),
            historySorted: []
          }]
        })

        expect(wrapper.vm.currentPage).toBe(1)
      }
    })
  })

  describe('totalPages computed', () => {
    it('computes totalPages from CVE count, not flat segments', () => {
      const wrapper = emptyWrapper()
      const cveCount = wrapper.vm.cveSnapshots.length
      const expectedPages = Math.max(1, Math.ceil(cveCount / 20))
      expect(wrapper.vm.totalPages).toBe(expectedPages)
    })
  })

  describe('DEMO data gating', () => {
    it('hides DEMO data when real ganttData is provided', () => {
      const realData = [
        {
          cve_id: 'CVE-REAL-001',
          severity: 'HIGH',
          description: 'Real vulnerability - test only',
          agent_name: 'srv-test-01',
          agent_id: 't-001',
          first_seen: '2026-01-01T00:00:00Z',
          historySorted: []
        }
      ]
      const wrapper = mount(GanttTab, {
        props: { ganttData: realData }
      })

      expect(wrapper.text()).not.toContain('DEMO')
      expect(wrapper.text()).toContain('CVE-REAL-001')
    })
  })

  describe('Loading state', () => {
    it('shows loading state when ganttData is null', () => {
      const wrapper = mount(GanttTab, {
        props: { ganttData: null }
      })

      expect(wrapper.text()).toContain('Cargando')
      expect(wrapper.find('.gantt-controls').exists()).toBe(false)
      expect(wrapper.find('.gantt-body').exists()).toBe(false)
    })
  })

  describe('Empty state fallback', () => {
    it('shows DEMO_SNAPSHOTS as fallback when ganttData is empty', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.find('.gantt-body').exists()).toBe(true)
      expect(wrapper.findAll('.gantt-bar').length).toBeGreaterThan(0)
    })
  })

  describe('Title', () => {
    it('shows title without "Criticos"', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.text()).toContain('Seguimiento de CVEs')
      expect(wrapper.text()).not.toContain('Criticos')
    })
  })

  describe('Tooltip interactions', () => {
    it('initial tooltip state is hidden', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.isHovering).toBe(false)
      expect(wrapper.vm.hoveredSnapshot).toBe(null)
      expect(wrapper.find('.gantt-tooltip').exists()).toBe(false)
    })

    it('handleBarMouseEnter sets hover state', () => {
      const wrapper = emptyWrapper()
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
      const wrapper = emptyWrapper()
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
      const wrapper = emptyWrapper()
      wrapper.vm.isHovering = true

      wrapper.vm.handleBarMouseMove({ clientX: 300, clientY: 150 })
      expect(wrapper.vm.tooltipPos.x).toBe(312)
      expect(wrapper.vm.tooltipPos.y).toBe(140)
    })
  })

  describe('getSnapshotBarClass (status-based)', () => {
    const makeCve = (snapshots) => ({ snapshots })

    it('returns snap-resolved when agentCount is 0', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 0 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 0)).toBe('snap-resolved')
    })

    it('returns snap-detected when first snapshot has agents', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 2 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 0)).toBe('snap-detected')
    })

    it('returns snap-detected when agentCount > 0 and previous was also > 0', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 1 }, { agentCount: 3 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 1)).toBe('snap-detected')
    })

    it('returns snap-reopened when previous snapshot had 0 agents', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 0 }, { agentCount: 2 }])
      expect(wrapper.vm.getSnapshotBarClass(cve, 1)).toBe('snap-reopened')
    })
  })

  describe('getSnapshotStatusLabel', () => {
    const makeCve = (snapshots) => ({ snapshots })

    it('returns Resuelto for 0 agents', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 0 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 0)).toBe('Resuelto')
    })

    it('returns Activo for first snapshot with agents', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 1 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 0)).toBe('Activo')
    })

    it('returns Reabierto when previous snapshot had 0 agents', () => {
      const wrapper = emptyWrapper()
      const cve = makeCve([{ agentCount: 0 }, { agentCount: 3 }])
      expect(wrapper.vm.getSnapshotStatusLabel(cve, 1)).toBe('Reabierto')
    })
  })

  describe('CSS cleanup — title label style', () => {
    it('uses CSS class instead of inline style on searchDate label', () => {
      const wrapper = emptyWrapper()
      const label = wrapper.find('label[for="ganttSearchDate"]')
      expect(label.exists()).toBe(true)
      expect(label.attributes('style')).toBeUndefined()
    })
  })

  describe('Date picker and search', () => {
    it('onGanttDatePickerChange sets searchDate from Date object', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.onGanttDatePickerChange(new Date('2026-07-15T14:30:00'))
      expect(wrapper.vm.searchDate).toBe('2026-07-15T14:30')
    })

    it('onGanttDatePickerChange ignores null date', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.onGanttDatePickerChange(null)
      expect(wrapper.vm.searchDate).toBe('')
    })
  })

  describe('Bar click navigation', () => {
    it('handleBarClick navigates to timeline with query params', () => {
      const wrapper = emptyWrapper()
      const cve = {
        cve_id: 'CVE-TEST',
        snapshots: [
          { syncTimestamp: '2026-07-01T10:00:00', agents: ['agent-1', 'agent-2'] },
          { syncTimestamp: '2026-07-10T10:00:00' }
        ]
      }
      wrapper.vm.handleBarClick(cve, 0)
      expect(mockRouterPush).toHaveBeenCalledWith({
        path: '/timeline',
        query: { cve: 'CVE-TEST', agents: 'agent-1,agent-2', syncStart: '2026-07-01T10:00:00', syncEnd: '2026-07-10T10:00:00' }
      })
    })

    it('handleBarClick with no agents uses empty string', () => {
      const wrapper = emptyWrapper()
      const cve = {
        cve_id: 'CVE-NOAGENTS',
        snapshots: [{ syncTimestamp: '2026-07-01T10:00:00' }]
      }
      wrapper.vm.handleBarClick(cve, 0)
      expect(mockRouterPush).toHaveBeenCalledWith({
        path: '/timeline',
        query: { cve: 'CVE-NOAGENTS', agents: '', syncStart: '2026-07-01T10:00:00', syncEnd: expect.any(String) }
      })
    })
  })

  describe('Tooltip edge cases', () => {
    it('cancelLeaveTimeout clears the leave timeout', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.startLeaveTimeout()
      expect(wrapper.vm.leaveTimeout).not.toBeNull()
      wrapper.vm.cancelLeaveTimeout()
      expect(wrapper.vm.leaveTimeout).toBeNull()
    })

    it('handleBarMouseEnter clears existing leaveTimeout', () => {
      const wrapper = emptyWrapper()
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
  })

  describe('Pagination', () => {
    const manyCves = Array.from({ length: 25 }, (_, i) => ({
      cve_id: `CVE-PAG-${String(i + 1).padStart(4, '0')}`,
      severity: 'HIGH',
      description: `Pagination CVE ${i + 1}`,
      snapshots: [{ syncTimestamp: '2026-07-01T10:00:00', agentCount: 1 }]
    }))

    it('shows pagination when ganttData has more than 20 CVEs', () => {
      const wrapper = mount(GanttTab, { props: { ganttData: manyCves } })
      expect(wrapper.vm.totalPages).toBe(2)
      expect(wrapper.find('.gantt-pagination').exists()).toBe(true)
    })

    it('clicking Siguiente advances to page 2', async () => {
      const wrapper = mount(GanttTab, { props: { ganttData: manyCves } })
      expect(wrapper.vm.currentPage).toBe(1)

      await wrapper.find('.page-btn:last-child').trigger('click')
      expect(wrapper.vm.currentPage).toBe(2)
    })

    it('clicking Anterior goes back to page 1', async () => {
      const wrapper = mount(GanttTab, { props: { ganttData: manyCves } })
      wrapper.vm.currentPage = 2
      await wrapper.vm.$nextTick()

      const btns = wrapper.findAll('.page-btn')
      const prevBtn = btns[0]
      await prevBtn.trigger('click')
      expect(wrapper.vm.currentPage).toBe(1)
    })

    it('Anterior button is disabled on page 1', () => {
      const wrapper = mount(GanttTab, { props: { ganttData: manyCves } })
      const btns = wrapper.findAll('.page-btn')
      expect(btns[0].element.disabled).toBe(true)
    })

    it('Siguiente button is disabled on last page', async () => {
      const wrapper = mount(GanttTab, { props: { ganttData: manyCves } })
      wrapper.vm.currentPage = 2
      await wrapper.vm.$nextTick()
      const btns = wrapper.findAll('.page-btn')
      expect(btns[1].element.disabled).toBe(true)
    })
  })
})
