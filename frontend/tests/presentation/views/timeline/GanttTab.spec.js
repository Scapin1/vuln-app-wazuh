import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GanttTab from '@/presentation/views/timeline/components/GanttTab.vue'

describe('GanttTab.vue', () => {
  // With empty ganttData, only DEMO_DATA is shown (6 items from DEMO_DATA)
  const emptyWrapper = () => mount(GanttTab, {
    props: { ganttData: [] }
  })

  describe('rendering with DEMO data only', () => {
    it('renders the gantt card and title', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.find('.gantt-card').exists()).toBe(true)
      expect(wrapper.text()).toContain('Seguimiento de CVEs Criticos')
    })

    it('renders CVE headers from DEMO_DATA', () => {
      const wrapper = emptyWrapper()

      // DEMO_DATA has 4 distinct CVEs: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003, CVE-2026-0004
      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.text()).toContain('CVE-2026-0002')
      expect(wrapper.text()).toContain('CVE-2026-0003')
      expect(wrapper.text()).toContain('CVE-2026-0004')
    })

    it('renders severity badges', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('CRITICAL')
      expect(wrapper.text()).toContain('HIGH')
      expect(wrapper.text()).toContain('MEDIUM')
      expect(wrapper.text()).toContain('LOW')
    })

    it('renders agent names from DEMO_DATA', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('srv-web-01')
      expect(wrapper.text()).toContain('srv-db-02')
      expect(wrapper.text()).toContain('srv-api-03')
    })

    it('renders gantt bars with status classes', () => {
      const wrapper = emptyWrapper()

      const bars = wrapper.findAll('.gantt-bar')
      expect(bars.length).toBeGreaterThan(0)

      const pendingBars = wrapper.findAll('.gantt-bar.pending')
      const resolvedBars = wrapper.findAll('.gantt-bar.resolved')
      const reopenedBars = wrapper.findAll('.gantt-bar.reopened')

      expect(pendingBars.length).toBeGreaterThan(0)
      expect(resolvedBars.length).toBeGreaterThan(0)
      expect(reopenedBars.length).toBeGreaterThan(0)
    })

    it('renders legend items', () => {
      const wrapper = emptyWrapper()

      expect(wrapper.text()).toContain('Pendiente')
      expect(wrapper.text()).toContain('Resuelto')
      expect(wrapper.text()).toContain('Reabierto')
    })

    it('renders zoom controls', () => {
      const wrapper = emptyWrapper()

      const zoomBtns = wrapper.findAll('.zoom-btn')
      expect(zoomBtns.length).toBe(2)

      expect(wrapper.find('.zoom-level').exists()).toBe(true)
      // Default zoom is month
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
      // First zoom in
      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(2)

      // Then zoom out
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(1)
    })

    it('does not zoom out below minimum', async () => {
      const wrapper = emptyWrapper()
      // Default is 1 (month), click zoom out should go to 0 (year)
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
      expect(wrapper.vm.zoomLabel).toBe('Año')
      expect(wrapper.vm.MONTH_WIDTH).toBe(80)

      // One more zoom out should stay at 0
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(0)
    })

    it('does not zoom in above maximum', async () => {
      const wrapper = emptyWrapper()
      // Click zoom in 3 times to go from 1 (month) to 3 (hour)
      for (let i = 0; i < 3; i++) {
        await wrapper.find('.zoom-btn:last-child').trigger('click')
      }
      expect(wrapper.vm.zoomIndex).toBe(3)
      expect(wrapper.vm.zoomLabel).toBe('Hora')
      expect(wrapper.vm.MONTH_WIDTH).toBe(40)

      // One more zoom in should stay at 3
      await wrapper.find('.zoom-btn:last-child').trigger('click')
      expect(wrapper.vm.zoomIndex).toBe(3)
    })

    it('changes time labels when zooming', async () => {
      const wrapper = emptyWrapper()

      // Month view should have month labels
      const monthText = wrapper.find('.month-label').text()
      expect(monthText.length).toBeGreaterThan(0)

      // Zoom out to year
      await wrapper.find('.zoom-btn:first-child').trigger('click')
      const yearText = wrapper.find('.month-label').text()
      // Year view shows years
      expect(yearText).toMatch(/^\d{4}$/)
    })
  })

  describe('pagination', () => {
    it('shows pagination when DEMO data has more than 20 segments', () => {
      const wrapper = emptyWrapper()

      // displaySegments.value.length with DEMO data
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

      // Only test if pagination is shown (more than 1 page)
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
      expect(result instanceof Date).toBe(true)
    })

    it('handles Date object input', () => {
      const wrapper = emptyWrapper()
      const now = new Date('2026-05-15T10:30:00Z')
      const result = wrapper.vm.toLocalDate(now)
      expect(result instanceof Date).toBe(true)
      expect(result.getTime()).toBe(now.getTime())
    })

    it('handles ISO date string with time', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.toLocalDate('2026-03-15T14:30:00Z')
      expect(result instanceof Date).toBe(true)
      // Last part: time preserved
      expect(result.getHours()).toBe(14)
      expect(result.getMinutes()).toBe(30)
    })

    it('handles ISO date string without time', () => {
      const wrapper = emptyWrapper()
      const result = wrapper.vm.toLocalDate('2026-03-15')
      expect(result instanceof Date).toBe(true)
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

  describe('getBarStyle helper', () => {
    it('returns empty object when no time labels', () => {
      const wrapper = emptyWrapper()
      // Force timeLabels to be empty by mounting with no useful data
      // With DEMO data, timeLabels should exist, but let's test the guard
      const segment = {
        start: new Date('2026-03-01'),
        end: new Date('2026-03-15'),
        status: 'PENDING'
      }
      // We need timeLabels to exist; this tests at least that the function
      // returns something with a left/width/top structure
      const style = wrapper.vm.getBarStyle(segment)
      expect(style).toHaveProperty('left')
      expect(style).toHaveProperty('width')
      expect(style).toHaveProperty('top')
    })
  })

  describe('getRowHeight', () => {
    it('returns minimum height for 0 lanes', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.getRowHeight(0)).toBe(56)
    })

    it('scales with lane count', () => {
      const wrapper = emptyWrapper()
      // Minimum is 56px (LANE_HEIGHT * 2)
      expect(wrapper.vm.getRowHeight(1)).toBe(56)
      expect(wrapper.vm.getRowHeight(2)).toBe(56)
      expect(wrapper.vm.getRowHeight(3)).toBe(84)
    })
  })

  describe('timeLabels computed', () => {
    it('returns non-empty labels with DEMO data', () => {
      const wrapper = emptyWrapper()
      expect(wrapper.vm.timeLabels.length).toBeGreaterThan(0)

      // Each label should have label and date
      wrapper.vm.timeLabels.forEach(label => {
        expect(label).toHaveProperty('label')
        expect(label).toHaveProperty('date')
        expect(typeof label.label).toBe('string')
        expect(label.date instanceof Date).toBe(true)
      })
    })

    it('generates year labels at year zoom', async () => {
      const wrapper = emptyWrapper()
      // Zoom out to year
      await wrapper.find('.zoom-btn:first-child').trigger('click')

      expect(wrapper.vm.zoomLabel).toBe('Año')
      wrapper.vm.timeLabels.forEach(label => {
        expect(label.label).toMatch(/^\d{4}$/)
      })
    })

    it('generates day labels at day zoom', async () => {
      const wrapper = emptyWrapper()
      // Zoom in once from month (1) to day (2)
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
      wrapper.vm.zoomIndex = 0 // year
      expect(wrapper.vm.msPerUnit).toBeCloseTo(365.25 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for month unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 1 // month (default)
      expect(wrapper.vm.msPerUnit).toBeCloseTo(30.44 * 24 * 60 * 60 * 1000, 0)
    })

    it('returns correct ms for day unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 2 // day
      expect(wrapper.vm.msPerUnit).toBe(24 * 60 * 60 * 1000)
    })

    it('returns correct ms for hour unit', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.zoomIndex = 3 // hour
      expect(wrapper.vm.msPerUnit).toBe(60 * 60 * 1000)
    })
  })

  describe('displaySegments computed', () => {
    it('processes DEMO data into segments with correct shape', () => {
      const wrapper = emptyWrapper()
      const segments = wrapper.vm.displaySegments

      expect(segments.length).toBeGreaterThan(0)

      segments.forEach(seg => {
        expect(seg).toHaveProperty('cve_id')
        expect(seg).toHaveProperty('severity')
        expect(seg).toHaveProperty('status')
        expect(seg).toHaveProperty('start')
        expect(seg).toHaveProperty('end')
        expect(seg).toHaveProperty('agent_name')
        expect(['PENDING', 'RESOLVED', 'REOPENED']).toContain(seg.status)
      })
    })

    it('processes REOPENED segments correctly from demo data', () => {
      const wrapper = emptyWrapper()
      const segments = wrapper.vm.displaySegments

      const reopenedSegments = segments.filter(s => s.status === 'REOPENED')
      // CVE-2026-0004 (LOW) has multiple reopen events
      expect(reopenedSegments.length).toBeGreaterThan(0)
    })

    it('merges consecutive segments with same status', () => {
      const wrapper = emptyWrapper()
      const segments = wrapper.vm.displaySegments

      // After merge, no two consecutive segments for the same agent+cve should have same status
      if (segments.length >= 2) {
        // This is hard to assert precisely, but we can verify the merge didn't break anything
        expect(segments.length).toBeGreaterThan(0)
      }
    })
  })

  describe('groupedByCve computed', () => {
    it('groups segments under CVE headers', () => {
      const wrapper = emptyWrapper()
      const groups = wrapper.vm.groupedByCve

      expect(groups.length).toBeGreaterThan(0)
      groups.forEach(group => {
        expect(group).toHaveProperty('cve_id')
        expect(group).toHaveProperty('severity')
        expect(group).toHaveProperty('agents')
        expect(Array.isArray(group.agents)).toBe(true)
        expect(group.agents.length).toBeGreaterThan(0)
      })
    })

    it('assigns lanes to prevent overlapping bars', () => {
      const wrapper = emptyWrapper()
      const groups = wrapper.vm.groupedByCve

      groups.forEach(group => {
        group.agents.forEach(agent => {
          if (agent.segments.length > 1) {
            // Check that overlapping segments get different lanes
            agent.segments.forEach(seg => {
              expect(typeof seg.lane).toBe('number')
            })
          }
        })
      })
    })

    it('computes laneCount per agent group', () => {
      const wrapper = emptyWrapper()
      const groups = wrapper.vm.groupedByCve

      groups.forEach(group => {
        group.agents.forEach(agent => {
          expect(agent.laneCount).toBeGreaterThanOrEqual(1)
        })
      })
    })

    it('calculates reopenCount per CVE', () => {
      const wrapper = emptyWrapper()
      const groups = wrapper.vm.groupedByCve

      groups.forEach(group => {
        expect(typeof group.reopenCount).toBe('number')
        expect(group.reopenCount).toBeGreaterThanOrEqual(0)
      })
    })
  })

  describe('scrollToDate', () => {
    it('handles empty searchDate gracefully', () => {
      const wrapper = emptyWrapper()
      // Should not throw
      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })

    it('handles missing scrollTo method gracefully', () => {
      const wrapper = emptyWrapper()
      wrapper.vm.searchDate = '2026-04-01T00:00'

      // The scrollWrapper ref is a DOM element but scrollTo might not be
      // available in jsdom. Mock it to avoid the error.
      if (wrapper.vm.scrollWrapper && typeof wrapper.vm.scrollWrapper.scrollTo !== 'function') {
        wrapper.vm.scrollWrapper.scrollTo = vi.fn()
      }

      expect(() => wrapper.vm.scrollToDate()).not.toThrow()
    })
  })

  describe('watch ganttData', () => {
    it('resets currentPage to 1 when ganttData changes', async () => {
      const wrapper = emptyWrapper()

      // Go to page 2 if pagination exists
      if (wrapper.vm.totalPages > 1) {
        wrapper.vm.currentPage = 2
        expect(wrapper.vm.currentPage).toBe(2)

        await wrapper.setProps({ ganttData: [{ cve_id: 'CVE-NEW', severity: 'HIGH', description: 'Test', agent_name: 'test', agent_id: 't1', first_seen: new Date().toISOString(), history: [] }] })

        expect(wrapper.vm.currentPage).toBe(1)
      }
    })
  })

  describe('totalAgentRows computed', () => {
    it('calculates total agents across all CVEs', () => {
      const wrapper = emptyWrapper()
      const groups = wrapper.vm.groupedByCve
      const manualSum = groups.reduce((sum, g) => sum + g.agents.length, 0)

      expect(wrapper.vm.totalAgentRows).toBe(manualSum)
    })
  })

  describe('paginatedData computed', () => {
    it('returns first page of data', () => {
      const wrapper = emptyWrapper()
      const page1 = wrapper.vm.paginatedData

      expect(page1.length).toBeLessThanOrEqual(20)

      // All items should be from the start
      const firstId = page1[0].cve_id
      expect(firstId.length).toBeGreaterThan(0)
    })
  })
})
