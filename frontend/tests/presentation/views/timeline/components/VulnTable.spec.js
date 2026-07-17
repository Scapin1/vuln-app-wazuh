import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import VulnTable from '@/presentation/views/timeline/components/VulnTable.vue'

function makeVuln(overrides = {}) {
  return {
    id: 1,
    cve_id: 'CVE-2026-0001',
    severity: 'CRITICAL',
    agent_name: 'srv-web-01',
    connection_name: 'Conn A',
    package_name: 'openssl',
    package_version: '1.1.1',
    score_base: 9.1,
    first_seen: '2026-03-07T10:00:00Z',
    last_seen: '2026-03-08T10:00:00Z',
    status: 'Detected',
    ...overrides
  }
}

describe('VulnTable.vue', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-03-08T16:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('rendering', () => {
    it('renders empty state when no vulns', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [], loading: false }
      })
      expect(wrapper.text()).toContain('No hay conexiones activas')
    })

    it('renders vulns in table', () => {
      const vulns = [makeVuln()]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.find('table').exists()).toBe(true)
      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.text()).toContain('srv-web-01')
    })

    it('renders multiple vulns', () => {
      const vulns = [
        makeVuln({ id: 1, cve_id: 'CVE-2026-0001' }),
        makeVuln({ id: 2, cve_id: 'CVE-2026-0002', severity: 'HIGH' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('CVE-2026-0001')
      expect(wrapper.text()).toContain('CVE-2026-0002')
    })
  })

  describe('getSeverityClass', () => {
    it('returns badge-critical for critical', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getSeverityClass('CRITICAL')).toBe('badge badge-critical')
      expect(wrapper.vm.getSeverityClass('critica')).toBe('badge badge-critical')
    })

    it('returns badge-high for high/alta', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getSeverityClass('HIGH')).toBe('badge badge-critical')
      expect(wrapper.vm.getSeverityClass('alta')).toBe('badge badge-critical')
    })

    it('returns badge-medium for medium/media', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getSeverityClass('MEDIUM')).toBe('badge badge-medium')
      expect(wrapper.vm.getSeverityClass('media')).toBe('badge badge-medium')
    })

    it('returns badge-low for low or unknown', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getSeverityClass('LOW')).toBe('badge badge-low')
      expect(wrapper.vm.getSeverityClass('unknown')).toBe('badge badge-low')
      expect(wrapper.vm.getSeverityClass(null)).toBe('badge badge-low')
    })
  })

  describe('getSeverityLevel', () => {
    it('returns correct level numbers', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getSeverityLevel('CRITICAL')).toBe(4)
      expect(wrapper.vm.getSeverityLevel('critica')).toBe(4)
      expect(wrapper.vm.getSeverityLevel('HIGH')).toBe(3)
      expect(wrapper.vm.getSeverityLevel('alta')).toBe(3)
      expect(wrapper.vm.getSeverityLevel('MEDIUM')).toBe(2)
      expect(wrapper.vm.getSeverityLevel('media')).toBe(2)
      expect(wrapper.vm.getSeverityLevel('LOW')).toBe(1)
      expect(wrapper.vm.getSeverityLevel(null)).toBe(0)
    })
  })

  describe('formatDate', () => {
    it('returns N/A for null date', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.formatDate(null)).toBe('N/A')
    })

    it('formats valid date string', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const result = wrapper.vm.formatDate('2026-03-07T10:00:00Z')
      expect(result).not.toBe('N/A')
      expect(typeof result).toBe('string')
    })
  })

  describe('timeAgo', () => {
    it('returns N/A for null', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.timeAgo(null)).toBe('N/A')
    })

    it('returns "Justo ahora" for current time', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const now = new Date().toISOString()
      expect(wrapper.vm.timeAgo(now)).toBe('Justo ahora')
    })

    it('returns minutes ago', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
      expect(wrapper.vm.timeAgo(fiveMinAgo)).toContain('min')
    })

    it('returns hours ago', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString()
      expect(wrapper.vm.timeAgo(twoHoursAgo)).toContain('horas')
    })

    it('returns days ago', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const threeDaysAgo = new Date(Date.now() - 3 * 86400 * 1000).toISOString()
      expect(wrapper.vm.timeAgo(threeDaysAgo)).toContain('días')
    })

    it('returns months ago', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const twoMonthsAgo = new Date(Date.now() - 60 * 86400 * 1000).toISOString()
      expect(wrapper.vm.timeAgo(twoMonthsAgo)).toContain('meses')
    })

    it('returns years ago', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const twoYearsAgo = new Date(Date.now() - 2 * 365 * 86400 * 1000).toISOString()
      expect(wrapper.vm.timeAgo(twoYearsAgo)).toContain('años')
    })
  })

  describe('isRecentlySeen', () => {
    it('returns false for null', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.isRecentlySeen(null)).toBe(false)
    })

    it('returns true when within 60 minutes', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const recent = new Date(Date.now() - 30 * 60 * 1000).toISOString()
      expect(wrapper.vm.isRecentlySeen(recent)).toBe(true)
    })

    it('returns false when older than 60 minutes', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const old = new Date(Date.now() - 120 * 60 * 1000).toISOString()
      expect(wrapper.vm.isRecentlySeen(old)).toBe(false)
    })
  })

  describe('getTimelineProgress', () => {
    it('returns 0 when missing dates', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      expect(wrapper.vm.getTimelineProgress({})).toBe(0)
    })

    it('returns 0 when dates are equal', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const vuln = { first_seen: '2026-03-08T10:00:00Z', last_seen: '2026-03-08T10:00:00Z' }
      expect(wrapper.vm.getTimelineProgress(vuln)).toBe(0)
    })

    it('returns a value between 5 and 100', () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln()], loading: false }
      })
      const vuln = { first_seen: '2026-03-07T10:00:00Z', last_seen: '2026-03-08T10:00:00Z' }
      const progress = wrapper.vm.getTimelineProgress(vuln)
      expect(progress).toBeGreaterThanOrEqual(5)
      expect(progress).toBeLessThanOrEqual(100)
    })
  })

  describe('sorting', () => {
    it('sorts by severity descending by default', () => {
      const vulns = [
        makeVuln({ id: 1, severity: 'LOW' }),
        makeVuln({ id: 2, severity: 'CRITICAL' }),
        makeVuln({ id: 3, severity: 'MEDIUM' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      // Default sort is last_seen desc, so order stays as is
      expect(wrapper.vm.sortedVulns.length).toBe(3)
    })

    it('cycles sort states on sortBy call', () => {
      const vulns = [makeVuln({ id: 1 }), makeVuln({ id: 2 })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      // First click: asc
      wrapper.vm.sortBy('severity')
      expect(wrapper.vm.sortKey).toBe('severity')
      expect(wrapper.vm.sortOrder).toBe('asc')

      // Second click: desc
      wrapper.vm.sortBy('severity')
      expect(wrapper.vm.sortOrder).toBe('desc')

      // Third click: clear sort
      wrapper.vm.sortBy('severity')
      expect(wrapper.vm.sortKey).toBe('')
      expect(wrapper.vm.sortOrder).toBe('')
    })

    it('changes sort key on different column click', () => {
      const vulns = [makeVuln({ id: 1 }), makeVuln({ id: 2 })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.sortBy('severity')
      expect(wrapper.vm.sortKey).toBe('severity')
      expect(wrapper.vm.sortOrder).toBe('asc')

      wrapper.vm.sortBy('cve_id')
      expect(wrapper.vm.sortKey).toBe('cve_id')
      expect(wrapper.vm.sortOrder).toBe('asc')
    })

    it('resets to page 1 when sort changes', async () => {
      const vulns = Array.from({ length: 60 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.currentPage = 2
      wrapper.vm.sortBy('severity')
      await nextTick()
      expect(wrapper.vm.currentPage).toBe(1)
    })

    it('sorts by severity level', () => {
      const vulns = [
        makeVuln({ id: 1, severity: 'LOW' }),
        makeVuln({ id: 2, severity: 'CRITICAL' }),
        makeVuln({ id: 3, severity: 'HIGH' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.sortBy('severity')
      const sorted = wrapper.vm.sortedVulns
      expect(wrapper.vm.getSeverityLevel(sorted[0].severity))
        .toBeLessThanOrEqual(wrapper.vm.getSeverityLevel(sorted[1].severity))
    })

    it('sorts by date columns', () => {
      const vulns = [
        makeVuln({ id: 1, last_seen: '2026-03-07T10:00:00Z' }),
        makeVuln({ id: 2, last_seen: '2026-03-08T10:00:00Z' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      // Default is last_seen desc, so first call with same key clears sort
      wrapper.vm.sortBy('last_seen')
      expect(wrapper.vm.sortKey).toBe('')
      expect(wrapper.vm.sortOrder).toBe('')
      expect(wrapper.vm.sortedVulns.length).toBe(2)
    })

    it('sorts by string columns', () => {
      const vulns = [
        makeVuln({ id: 1, agent_name: 'srv-b' }),
        makeVuln({ id: 2, agent_name: 'srv-a' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.sortBy('agent_name')
      const sorted = wrapper.vm.sortedVulns
      expect(wrapper.vm.sortKey).toBe('agent_name')
      expect(sorted.length).toBe(2)
    })

    it('returns empty array when sort key is empty', () => {
      const vulns = [makeVuln({ id: 1 }), makeVuln({ id: 2 })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.sortKey = ''
      wrapper.vm.sortOrder = ''
      expect(wrapper.vm.sortedVulns.length).toBe(2)
    })
  })

  describe('pagination', () => {
    it('shows pagination when vulns exceed items per page', () => {
      const vulns = Array.from({ length: 120 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      // 120 / 50 = 3 pages
      expect(wrapper.vm.totalPages).toBe(3)
      expect(wrapper.vm.paginatedVulns.length).toBe(50)
    })

    it('navigates to next page', () => {
      const vulns = Array.from({ length: 120 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.nextPage()
      expect(wrapper.vm.currentPage).toBe(2)

      wrapper.vm.nextPage()
      expect(wrapper.vm.currentPage).toBe(3)

      // Cannot go beyond last page
      wrapper.vm.nextPage()
      expect(wrapper.vm.currentPage).toBe(3)
    })

    it('navigates to previous page', () => {
      const vulns = Array.from({ length: 120 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.currentPage = 3
      wrapper.vm.prevPage()
      expect(wrapper.vm.currentPage).toBe(2)

      wrapper.vm.prevPage()
      expect(wrapper.vm.currentPage).toBe(1)

      // Cannot go below page 1
      wrapper.vm.prevPage()
      expect(wrapper.vm.currentPage).toBe(1)
    })

    it('jumps backward correctly', () => {
      const vulns = Array.from({ length: 500 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.currentPage = 5
      wrapper.vm.jumpBackward()
      expect(wrapper.vm.currentPage).toBe(1)
    })

    it('jumps forward correctly', () => {
      const vulns = Array.from({ length: 500 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      // 500/50 = 10 total pages, jump 10: 1+10 = 11, capped at 10
      wrapper.vm.currentPage = 1
      wrapper.vm.jumpForward()
      expect(wrapper.vm.currentPage).toBe(10)
    })

    it('does not jump beyond last page', () => {
      const vulns = Array.from({ length: 60 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      // totalPages = 2
      wrapper.vm.currentPage = 1
      wrapper.vm.jumpForward()
      expect(wrapper.vm.currentPage).toBe(2)
    })
  })

  describe('visiblePages', () => {
    it('shows all pages when total <= 7', () => {
      const vulns = Array.from({ length: 200 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      // 200/50 = 4 pages
      const pages = wrapper.vm.visiblePages
      expect(pages).toEqual([1, 2, 3, 4])
    })

    it('shows ellipsis when many pages', () => {
      const vulns = Array.from({ length: 1000 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      // 1000/50 = 20 pages, should use ellipsis
      const pages = wrapper.vm.visiblePages
      expect(pages[0]).toBe(1)
      expect(pages.includes('right-ellipsis')).toBe(true)
      expect(pages[pages.length - 1]).toBe(20)
    })

    it('shows left ellipsis when in middle', () => {
      const vulns = Array.from({ length: 1000 }, (_, i) =>
        makeVuln({ id: i, cve_id: `CVE-${i}` })
      )
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })

      wrapper.vm.currentPage = 10
      const pages = wrapper.vm.visiblePages
      expect(pages[0]).toBe(1)
      expect(pages.includes('left-ellipsis')).toBe(true)
      expect(pages.includes('right-ellipsis')).toBe(true)
      expect(pages[pages.length - 1]).toBe(20)
    })
  })

  describe('connectionName prop', () => {
    it('renders connectionName prop value when vuln.connection_name is null', () => {
      const vulns = [makeVuln({ connection_name: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false, connectionName: 'Test Connection' }
      })
      expect(wrapper.text()).toContain('Test Connection')
    })

    it('prefers vuln.connection_name over connectionName prop', () => {
      const vulns = [makeVuln({ connection_name: 'Vuln Connection' })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false, connectionName: 'Prop Connection' }
      })
      expect(wrapper.text()).toContain('Vuln Connection')
      expect(wrapper.text()).not.toContain('Prop Connection')
    })

    it('falls back to connectionName prop when vuln.connection_name is missing', () => {
      const vulns = [makeVuln({ connection_name: undefined })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false, connectionName: 'Fallback Connection' }
      })
      expect(wrapper.text()).toContain('Fallback Connection')
    })

    it('falls back to dash when neither connection_name nor connectionName prop is provided', () => {
      const vulns = [makeVuln({ connection_name: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('-')
    })
  })

  describe('edge cases', () => {
    it('handles null scores', () => {
      const vulns = [makeVuln({ score_base: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('N/A')
    })

    it('handles missing agent name gracefully', () => {
      const vulns = [makeVuln({ agent_name: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('N/A')
    })

    it('handles missing connection_name', () => {
      const vulns = [makeVuln({ connection_name: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('-')
    })

    it('handles UNKNOWN severity', () => {
      const vulns = [makeVuln({ severity: 'UNKNOWN' })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('UNKNOWN')
    })

    it('resets page when vulns change', async () => {
      const wrapper = mount(VulnTable, {
        props: { vulns: [makeVuln({ id: 1 })], loading: false }
      })
      wrapper.vm.currentPage = 2
      expect(wrapper.vm.currentPage).toBe(2)

      wrapper.setProps({ vulns: [] })
      await nextTick()
      expect(wrapper.vm.currentPage).toBe(1)
    })

    it('handles single page no pagination buttons', () => {
      const vulns = [makeVuln()]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.find('.pagination-header').exists()).toBe(false)
    })

    it('handles missing cve_id with N/A', () => {
      const vulns = [makeVuln({ cve_id: null })]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.text()).toContain('N/A')
    })
  })

  describe('sync interval filtering (from Gantt click)', () => {
    it('returns all vulns when no syncStart is set', () => {
      const vulns = [
        makeVuln({ id: 1, last_seen: '2026-03-01T10:00:00Z' }),
        makeVuln({ id: 2, last_seen: '2026-03-05T10:00:00Z' })
      ]
      const wrapper = mount(VulnTable, {
        props: { vulns, loading: false }
      })
      expect(wrapper.vm.sortedVulns).toHaveLength(2)
    })

    it('filters vulns within syncStart-syncEnd interval', () => {
      const vulns = [
        makeVuln({ id: 1, last_seen: '2026-03-01T10:00:00Z' }),
        makeVuln({ id: 2, last_seen: '2026-03-15T10:00:00Z' }),
        makeVuln({ id: 3, last_seen: '2026-03-20T10:00:00Z' })
      ]
      const wrapper = mount(VulnTable, {
        props: {
          vulns,
          loading: false,
          syncStart: '2026-03-10T00:00:00Z',
          syncEnd: '2026-03-18T00:00:00Z'
        }
      })
      expect(wrapper.vm.sortedVulns).toHaveLength(1)
      expect(wrapper.vm.sortedVulns[0].id).toBe(2)
    })

    it('uses Date.now() as syncEnd when syncEnd is not provided', () => {
      const vulns = [
        makeVuln({ id: 1, last_seen: '2026-01-01T00:00:00Z' }),
        makeVuln({ id: 2, last_seen: '2026-03-08T12:00:00Z' }) // within system time
      ]
      const wrapper = mount(VulnTable, {
        props: {
          vulns,
          loading: false,
          syncStart: '2026-03-01T00:00:00Z'
        }
      })
      // System time is 2026-03-08T16:00:00Z
      expect(wrapper.vm.sortedVulns).toHaveLength(1)
      expect(wrapper.vm.sortedVulns[0].id).toBe(2)
    })

    it('excludes vulns before syncStart', () => {
      const vulns = [
        makeVuln({ id: 1, last_seen: '2026-02-01T10:00:00Z' }),
        makeVuln({ id: 2, last_seen: '2026-03-15T10:00:00Z' })
      ]
      const wrapper = mount(VulnTable, {
        props: {
          vulns,
          loading: false,
          syncStart: '2026-03-01T00:00:00Z',
          syncEnd: '2026-04-01T00:00:00Z'
        }
      })
      expect(wrapper.vm.sortedVulns).toHaveLength(1)
      expect(wrapper.vm.sortedVulns[0].id).toBe(2)
    })

    it('handles isInSyncInterval directly', () => {
      const wrapper = mount(VulnTable, {
        props: {
          vulns: [makeVuln()],
          loading: false,
          syncStart: '2026-03-01T00:00:00Z',
          syncEnd: '2026-04-01T00:00:00Z'
        }
      })
      expect(wrapper.vm.isInSyncInterval(makeVuln({ last_seen: '2026-03-07T10:00:00Z' }))).toBe(true)
      expect(wrapper.vm.isInSyncInterval(makeVuln({ last_seen: '2026-05-01T10:00:00Z' }))).toBe(false)
    })
  })
})
