import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useVulnStore } from '@/application/stores/vulnStore'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getVulns: vi.fn(),
    getDashboardSummary: vi.fn(),
    getTimeline: vi.fn(),
    getAnalytics: vi.fn(),
    getFilterOptions: vi.fn(),
    getTimelineEvents: vi.fn()
  }
}))

// Minimal mock data
const mockVuln = (overrides = {}) => ({
  cve_id: 'CVE-2026-0001',
  severity: 'CRITICAL',
  status: 'Detected',
  agent_name: 'srv-a',
  first_seen: '2026-03-08T10:00:00Z',
  last_seen: '2026-03-08T12:00:00Z',
  ...overrides
})

describe('vulnStore.js', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useVulnStore()
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-03-08T16:00:00Z'))
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // ── filterByPeriod ──

  it('filterByPeriod returns all vulns when period is "all"', () => {
    const vulns = [mockVuln(), mockVuln({ cve_id: 'CVE-2' })]
    const result = store.filterByPeriod(vulns, 'all')
    expect(result).toEqual(vulns)
  })

  it('filterByPeriod returns all vulns when period is null', () => {
    const vulns = [mockVuln()]
    const result = store.filterByPeriod(vulns, null)
    expect(result).toEqual(vulns)
  })

  it('filterByPeriod filters by 24h period', () => {
    const recent = mockVuln({ last_seen: new Date().toISOString() })
    const old = mockVuln({ cve_id: 'CVE-2', last_seen: '2026-03-01T10:00:00Z' })
    const vulns = [recent, old]

    const result = store.filterByPeriod(vulns, '24h')
    expect(result).toHaveLength(1)
    expect(result[0].cve_id).toBe('CVE-2026-0001')
  })

  it('filterByPeriod filters by 7d period', () => {
    const recent = mockVuln({ last_seen: '2026-03-07T10:00:00Z' })
    const old = mockVuln({ cve_id: 'CVE-2', last_seen: '2026-02-01T10:00:00Z' })
    const vulns = [recent, old]

    const result = store.filterByPeriod(vulns, '7d')
    expect(result).toHaveLength(1)
  })

  it('filterByPeriod filters by 30d period', () => {
    const recent = mockVuln({ last_seen: '2026-03-01T10:00:00Z' })
    const old = mockVuln({ cve_id: 'CVE-2', last_seen: '2025-01-01T00:00:00Z' })
    const vulns = [recent, old]

    const result = store.filterByPeriod(vulns, '30d')
    expect(result).toHaveLength(1)
  })

  it('filterByPeriod handles "day" period with customDate', () => {
    const inside = mockVuln({ first_seen: '2026-03-08T10:00:00Z' })
    const outside = mockVuln({ cve_id: 'CVE-2', first_seen: '2026-03-07T23:00:00Z' })
    const vulns = [inside, outside]

    const result = store.filterByPeriod(vulns, 'day', '2026-03-08')
    expect(result).toHaveLength(1)
    expect(result[0].cve_id).toBe('CVE-2026-0001')
  })

  it('filterByPeriod returns all vulns for unknown period', () => {
    const vulns = [mockVuln()]
    const result = store.filterByPeriod(vulns, 'unknown')
    expect(result).toEqual(vulns)
  })

  // ── clearConnectionData ──

  it('clearConnectionData resets dashboardVulns', () => {
    store.dashboardVulns = [mockVuln()]
    store.clearConnectionData()
    expect(store.dashboardVulns).toEqual([])
  })

  // ── invalidateCache ──

  it('invalidateCache clears the cache (triggers refetch)', async () => {
    // Populate cache via successful API call
    const apiData1 = { severity_distribution: {}, status_distribution: {}, total: 5 }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData1 })
    await store.fetchDashboardSummary('conn-1')

    // Cache is now populated — second call should use cache without calling API
    vulnService.getDashboardSummary.mockClear()
    const cached = await store.fetchDashboardSummary('conn-1')
    expect(vulnService.getDashboardSummary).not.toHaveBeenCalled()
    expect(cached.total).toBe(5)

    // Invalidate cache
    store.invalidateCache()

    // Third call should hit API again (cache was cleared)
    const apiData2 = { severity_distribution: {}, status_distribution: {}, total: 10 }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData2 })
    const refetched = await store.fetchDashboardSummary('conn-1')
    expect(vulnService.getDashboardSummary).toHaveBeenCalledTimes(1)
    expect(refetched.total).toBe(10)
  })

  // ── fetchDashboardSummary (API success) ──

  it('fetchDashboardSummary returns data from API', async () => {
    const apiData = {
      severity_distribution: { CRITICAL: 2, HIGH: 1, MEDIUM: 0, LOW: 0 },
      status_distribution: { Detected: 2, Resolved: 1, 'Re-emerged': 0 },
      total: 3
    }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData })

    const result = await store.fetchDashboardSummary('conn-1', '30d')

    expect(vulnService.getDashboardSummary).toHaveBeenCalledWith('conn-1', '30d', undefined)
    expect(result).toEqual(apiData)
    expect(store.loading).toBe(false)
  })

  it('fetchDashboardSummary falls back to client-side when API fails', async () => {
    vulnService.getDashboardSummary.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockResolvedValueOnce({ data: [mockVuln(), mockVuln({ cve_id: 'CVE-2', severity: 'HIGH' })] })

    const result = await store.fetchDashboardSummary('conn-1', 'all')

    expect(result.severity_distribution).toBeDefined()
    expect(result.status_distribution).toBeDefined()
    expect(result.total).toBe(2)
    expect(store.loading).toBe(false)
  })

  // ── fetchAnalytics (API success) ──

  it('fetchAnalytics returns data from API', async () => {
    const apiData = {
      severity_distribution: { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0 },
      status_distribution: { Activo: 2 },
      top_agents: [{ agent: 'srv-a', count: 2 }],
      critical_count: 2,
      top_critical_cve: 'CVE-2026-0001'
    }
    vulnService.getAnalytics.mockResolvedValueOnce({ data: apiData })

    const result = await store.fetchAnalytics('conn-1', '30d')

    expect(vulnService.getAnalytics).toHaveBeenCalledWith('conn-1', '30d', undefined)
    expect(result).toEqual(apiData)
    expect(store.loading).toBe(false)
  })

  it('fetchAnalytics re-throws API error instead of client fallback', async () => {
    vulnService.getAnalytics.mockRejectedValueOnce(new Error('API down'))

    await expect(store.fetchAnalytics('conn-1', 'all')).rejects.toThrow('API down')
    expect(store.loading).toBe(false)
  })

  // ── fetchFilterOptions (API success) ──

  it('fetchFilterOptions returns data from API', async () => {
    const apiData = { agents: ['srv-a', 'srv-b'], cves: ['CVE-1', 'CVE-2'] }
    vulnService.getFilterOptions.mockResolvedValueOnce({ data: apiData })

    const result = await store.fetchFilterOptions('conn-1')

    expect(vulnService.getFilterOptions).toHaveBeenCalledWith('conn-1')
    expect(result).toEqual(apiData)
    expect(store.loading).toBe(false)
  })

  it('fetchFilterOptions re-throws API error instead of client fallback', async () => {
    vulnService.getFilterOptions.mockRejectedValueOnce(new Error('API down'))

    await expect(store.fetchFilterOptions('conn-1')).rejects.toThrow('API down')
    expect(store.loading).toBe(false)
  })

  // ── fetchTimelineEvents (API success) ──

  it('fetchTimelineEvents returns data from API', async () => {
    const apiData = { detections: [], resolutions: [] }
    vulnService.getTimelineEvents.mockResolvedValueOnce({ data: apiData })

    const result = await store.fetchTimelineEvents('conn-1', 1700000000000, 1700086400000)

    expect(vulnService.getTimelineEvents).toHaveBeenCalledWith('conn-1', 1700000000000, 1700086400000)
    expect(result).toEqual(apiData)
    expect(store.loading).toBe(false)
  })

  it('fetchTimelineEvents falls back to client-side when API fails', async () => {
    vulnService.getTimelineEvents.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockResolvedValueOnce({ data: [] })

    const result = await store.fetchTimelineEvents('conn-1', 0, 9999999999999)

    expect(result.detections).toEqual([])
    expect(result.resolutions).toEqual([])
    expect(store.loading).toBe(false)
  })

  // ── buildCveSnapshots ──

  it('buildCveSnapshots groups vulns by CVE', () => {
    const vulns = [
      mockVuln({ cve_id: 'CVE-A', agent_name: 'srv-a' }),
      mockVuln({ cve_id: 'CVE-A', agent_name: 'srv-b' }),
      mockVuln({ cve_id: 'CVE-B', agent_name: 'srv-a' })
    ]

    const result = store.buildCveSnapshots(vulns)

    expect(result).toHaveLength(2)
    const cveA = result.find(c => c.cve_id === 'CVE-A')
    const cveB = result.find(c => c.cve_id === 'CVE-B')
    expect(cveA.agents).toHaveLength(2)
    expect(cveB.agents).toHaveLength(1)
  })

  it('buildCveSnapshots calculates isResolved correctly', () => {
    const vulns = [
      mockVuln({
        cve_id: 'CVE-A',
        historySorted: [{ timestamp: '2026-03-08T14:00:00Z', action: 'RESOLVED' }]
      })
    ]

    const result = store.buildCveSnapshots(vulns)
    expect(result[0].isResolved).toBe(true)
  })

  // ── Cache behavior ──

  it('returns cached data on second call within TTL', async () => {
    const apiData = { severity_distribution: {}, status_distribution: {}, total: 0 }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData })

    const first = await store.fetchDashboardSummary('conn-1')
    const second = await store.fetchDashboardSummary('conn-1')

    // API should only be called once (second call hits cache)
    expect(vulnService.getDashboardSummary).toHaveBeenCalledTimes(1)
    expect(first).toEqual(second)
  })

  it('refetches after cache TTL expires', async () => {
    const apiData1 = { total: 5 }
    const apiData2 = { total: 10 }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData1 })
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: apiData2 })

    await store.fetchDashboardSummary('conn-1')

    // Advance time past TTL
    vi.advanceTimersByTime(61000)

    await store.fetchDashboardSummary('conn-1')

    expect(vulnService.getDashboardSummary).toHaveBeenCalledTimes(2)
  })

  // ── fetchDashboard ──

  it('fetchDashboard returns cached data on cache hit', async () => {
    // Populate cache via successful API
    const summary = { severity_distribution: {}, status_distribution: {}, total: 0 }
    const timeline = { cves: [{ cve_id: 'CVE-1' }] }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: summary })
    vulnService.getTimeline.mockResolvedValueOnce({ data: timeline })

    await store.fetchDashboard('conn-1', '30d')

    // Second call uses cache
    vulnService.getDashboardSummary.mockClear()
    vulnService.getTimeline.mockClear()
    const cached = await store.fetchDashboard('conn-1', '30d')

    expect(vulnService.getDashboardSummary).not.toHaveBeenCalled()
    expect(cached.summary).toEqual(summary)
    expect(cached.vulns).toEqual(timeline.cves)
  })

  it('fetchDashboard uses both APIs when available', async () => {
    const summary = { severity_distribution: {}, status_distribution: {}, total: 5 }
    const timeline = { cves: [{ cve_id: 'CVE-A' }, { cve_id: 'CVE-B' }] }
    vulnService.getDashboardSummary.mockResolvedValueOnce({ data: summary })
    vulnService.getTimeline.mockResolvedValueOnce({ data: timeline })

    const result = await store.fetchDashboard('conn-1', '30d')

    expect(vulnService.getDashboardSummary).toHaveBeenCalledWith('conn-1', '30d', undefined)
    expect(vulnService.getTimeline).toHaveBeenCalledWith('conn-1', '30d', undefined, 1, 200, {})
    expect(result.summary).toEqual(summary)
    expect(result.vulns).toEqual(timeline.cves)
    expect(store.dashboardVulns).toEqual(timeline.cves)
    expect(store.loading).toBe(false)
  })

  it('fetchDashboard falls back when both APIs fail', async () => {
    vulnService.getDashboardSummary.mockRejectedValueOnce(new Error('API down'))
    vulnService.getTimeline.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockResolvedValueOnce({ data: [mockVuln(), mockVuln({ cve_id: 'CVE-2' })] })

    const result = await store.fetchDashboard('conn-1', 'all')

    expect(result.summary.total).toBe(2)
    expect(result.vulns).toHaveLength(2)
    expect(store.dashboardVulns).toHaveLength(2)
    expect(store.loading).toBe(false)
  })

  it('fetchDashboard throws error when everything fails', async () => {
    vulnService.getDashboardSummary.mockRejectedValueOnce(new Error('API down'))
    vulnService.getTimeline.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockRejectedValueOnce(new Error('DB down'))

    await expect(store.fetchDashboard('conn-1', '30d')).rejects.toThrow('DB down')
    expect(store.loading).toBe(false)
    expect(store.error).toBe('DB down')
  })

  // ── fetchTimeline ──

  it('fetchTimeline returns cached data on cache hit', async () => {
    const data = { cves: [], total_cves: 0, total_pages: 1, current_page: 1, per_page: 20 }
    vulnService.getTimeline.mockResolvedValueOnce({ data })

    await store.fetchTimeline('conn-1', '30d', null, 1, 20, {})

    // Second call — same params should hit cache
    vulnService.getTimeline.mockClear()
    const cached = await store.fetchTimeline('conn-1', '30d', null, 1, 20, {})
    expect(vulnService.getTimeline).not.toHaveBeenCalled()
    expect(cached.total_cves).toBe(0)
  })

  it('fetchTimeline returns data from API', async () => {
    const data = { cves: [{ cve_id: 'CVE-1' }], total_cves: 1, total_pages: 1, current_page: 1, per_page: 20 }
    vulnService.getTimeline.mockResolvedValueOnce({ data })

    const result = await store.fetchTimeline('conn-1', '30d')

    expect(vulnService.getTimeline).toHaveBeenCalledWith('conn-1', '30d', undefined, 1, 20, {})
    expect(result.total_cves).toBe(1)
    expect(result.cves).toHaveLength(1)
    expect(store.loading).toBe(false)
  })

  it('fetchTimeline re-throws API error instead of client fallback', async () => {
    vulnService.getTimeline.mockRejectedValueOnce(new Error('API down'))

    await expect(store.fetchTimeline('conn-1', 'all')).rejects.toThrow('API down')
    expect(store.loading).toBe(false)
  })

  // ── fetchTimelineEvents fallback edge cases ──

  it('fetchTimelineEvents fallback detects resolution events from history', async () => {
    vulnService.getTimelineEvents.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockResolvedValueOnce({
      data: [mockVuln({
        historySorted: [{ timestamp: '2026-03-08T12:00:00Z', action: 'RESOLVED' }]
      })]
    })

    const result = await store.fetchTimelineEvents('conn-1', 1700000000000, 9999999999999)

    expect(result.detections).toHaveLength(1)
    expect(result.resolutions).toHaveLength(1)
    expect(result.resolutions[0].cve_id).toBe('CVE-2026-0001')
    expect(store.loading).toBe(false)
  })

  it('fetchTimelineEvents fallback only includes events within range', async () => {
    vulnService.getTimelineEvents.mockRejectedValueOnce(new Error('API down'))
    vulnService.getVulns.mockResolvedValueOnce({
      data: [mockVuln({
        first_seen: '2026-03-08T10:00:00Z',
        historySorted: [{ timestamp: '2099-01-01T00:00:00Z', action: 'RESOLVED' }]
      })]
    })

    const result = await store.fetchTimelineEvents('conn-1', 1700000000000, 1800000000000)

    // detection is within range, resolution is outside range
    expect(result.detections).toHaveLength(1)
    expect(result.resolutions).toHaveLength(0)
  })

  // ── fetchFilterOptions fallback handles no data ──

  it('fetchFilterOptions re-throws error on empty vulns (no fallback)', async () => {
    vulnService.getFilterOptions.mockRejectedValueOnce(new Error('API down'))

    await expect(store.fetchFilterOptions('conn-1')).rejects.toThrow('API down')
    expect(store.loading).toBe(false)
  })

  // ── Loading/error state ──

  it('sets loading state during fetch', async () => {
    let resolve
    vulnService.getDashboardSummary.mockImplementationOnce(() => new Promise(r => { resolve = r }))

    const promise = store.fetchDashboardSummary('conn-1')
    expect(store.loading).toBe(true)

    resolve({ data: { severity_distribution: {}, status_distribution: {}, total: 0 } })
    await promise
    expect(store.loading).toBe(false)
  })

  it('sets error state on fetchDashboardSummary failure', async () => {
    vulnService.getDashboardSummary.mockRejectedValueOnce(new Error('API error'))
    vulnService.getVulns.mockRejectedValueOnce(new Error('Fallback error'))

    await expect(store.fetchDashboardSummary('conn-1')).rejects.toThrow()
  })

  // ── activeConnectionId tracking ──

  it('tracks activeConnectionId across calls', async () => {
    vulnService.getDashboardSummary.mockResolvedValue({ data: { severity_distribution: {}, status_distribution: {}, total: 0 } })

    await store.fetchDashboardSummary('conn-a')
    expect(store.activeConnectionId).toBe('conn-a')

    await store.fetchDashboardSummary('conn-b')
    expect(store.activeConnectionId).toBe('conn-b')
  })
})
