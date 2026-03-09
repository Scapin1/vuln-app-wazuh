import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref } from 'vue'
import useTimelineData from '@/presentation/views/timeline/useTimelineData'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getVulns: vi.fn()
  }
}))

describe('useTimelineData', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('builds slots and computes latest snapshot', async () => {
    vulnService.getVulns.mockResolvedValueOnce({
      data: [
        {
          id: 1,
          agent_name: 'srv-01',
          cve_id: 'CVE-123',
          first_seen: '2026-03-07T10:00:00Z',
          history: [{ timestamp: '2026-03-07T12:00:00Z', action: 'RESOLVED' }]
        }
      ]
    })

    const selectedConnection = ref('1')
    const selectedAgents = ref([])
    const selectedVulns = ref([])
    const period = ref('7d')
    const customDate = ref('2026-03-08')
    const activeZoom = ref({ slotHours: 24 })

    const timeline = useTimelineData({
      selectedConnection,
      selectedAgents,
      selectedVulns,
      period,
      customDate,
      activeZoom,
      getConnectionName: () => 'Demo Conn'
    })

    const result = await timeline.build()

    expect(result.initialZoom).toBe(2)
    expect(timeline.hasBuilt.value).toBe(true)
    expect(timeline.allSlots.value.length).toBeGreaterThan(0)
    expect(timeline.latestSnap.value.total).toBe(1)
    // connection_name should be assigned using fallback function
    expect(timeline.latestSnap.value.details[0].connection_name).toBe('Demo Conn')
  })

  it('sets warning when limit threshold is reached', async () => {
    vulnService.getVulns.mockResolvedValueOnce({
      data: Array.from({ length: 2000 }).map((_, index) => ({
        id: index,
        first_seen: '2026-03-07T10:00:00Z',
        history: []
      }))
    })

    const timeline = useTimelineData({
      selectedConnection: ref('1'),
      selectedAgents: ref([]),
      selectedVulns: ref([]),
      period: ref('24h'),
      customDate: ref('2026-03-08'),
      activeZoom: ref({ slotHours: 24 }),
      getConnectionName: () => 'Conn'
    })

    await timeline.fetchConnectionVulns()

    expect(timeline.warningMessage.value).toContain('2000')
  })
})
