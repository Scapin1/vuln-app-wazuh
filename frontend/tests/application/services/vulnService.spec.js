import { describe, it, expect, vi } from 'vitest'
import vulnService from '@/application/services/vulnService'
import apiClient from '@/infrastructure/http/apiClient'

// Mock the apiClient module
vi.mock('@/infrastructure/http/apiClient', () => {
    return {
        default: {
            get: vi.fn(),
            post: vi.fn(),
        }
    }
})

describe('vulnService.js', () => {

    // ── getVulns ──

    it('getVulns calls apiClient.get with default params when empty', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns()

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {}
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns includes limit and connection_id when provided', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns({ limit: 50, connectionId: 2 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                limit: 50,
                connection_id: 2,
            }
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns includes offset when provided', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        await vulnService.getVulns({ offset: 100 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: { offset: 100 }
        })
    })

    it('getVulns skips null/undefined params', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        await vulnService.getVulns({ limit: null, connectionId: undefined })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {}
        })
    })

    it('getVulns spreads extraConfig to request', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)
        const signal = new AbortController().signal

        await vulnService.getVulns({ limit: 10 }, { signal })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: { limit: 10 },
            signal
        })
    })

    // ── syncVulns ──

    it('syncVulns calls apiClient.post on /vulns/sync-all', async () => {
        const mockResponse = { data: { synced: 10 } }

        apiClient.post.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.syncVulns()

        expect(apiClient.post).toHaveBeenCalledWith('/vulns/sync-all')
        expect(result).toEqual(mockResponse)
    })

    // ── getDashboardSummary ──

    it('getDashboardSummary calls /vulns/dashboard with default period', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getDashboardSummary('conn-1')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/dashboard', {
            params: {
                connection_id: 'conn-1',
                period: '30d',
                date: undefined
            }
        })
    })

    it('getDashboardSummary uses provided period and customDate', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getDashboardSummary('conn-1', '7d', '2026-03-08')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/dashboard', {
            params: {
                connection_id: 'conn-1',
                period: '7d',
                date: '2026-03-08'
            }
        })
    })

    // ── getTimeline ──

    it('getTimeline calls /vulns/timeline/gantt with defaults', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getTimeline('conn-1')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/timeline/gantt', {
            params: {
                connection_id: 'conn-1',
                period: 'all',
                date: undefined,
                page: 1,
                per_page: 20
            }
        })
    })

    it('getTimeline includes optional filters', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getTimeline('conn-1', '30d', '2026-03-08', 2, 50, {
            agent: 'srv-a',
            severity: 'CRITICAL',
            search: 'CVE-2026'
        })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/timeline/gantt', {
            params: {
                connection_id: 'conn-1',
                period: '30d',
                date: '2026-03-08',
                page: 2,
                per_page: 50,
                agent: 'srv-a',
                severity: 'CRITICAL',
                search: 'CVE-2026'
            }
        })
    })

    it('getTimeline handles empty filters', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getTimeline('conn-1', 'all', undefined, 1, 20, {})

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/timeline/gantt', {
            params: {
                connection_id: 'conn-1',
                period: 'all',
                date: undefined,
                page: 1,
                per_page: 20
            }
        })
    })

    // ── getAnalytics ──

    it('getAnalytics calls /vulns/analytics with default period', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getAnalytics('conn-1')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/analytics', {
            params: {
                connection_id: 'conn-1',
                period: '30d',
                date: undefined
            }
        })
    })

    it('getAnalytics uses provided period and date', async () => {
        apiClient.get.mockResolvedValueOnce({ data: {} })

        await vulnService.getAnalytics('conn-1', '7d', '2026-03-08')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/analytics', {
            params: {
                connection_id: 'conn-1',
                period: '7d',
                date: '2026-03-08'
            }
        })
    })

    // ── getFilterOptions ──

    it('getFilterOptions calls /vulns/filter-options', async () => {
        apiClient.get.mockResolvedValueOnce({ data: { agents: [], cves: [] } })

        const result = await vulnService.getFilterOptions('conn-1')

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/filter-options', {
            params: { connection_id: 'conn-1' }
        })
        expect(result.data).toEqual({ agents: [], cves: [] })
    })

    // ── getTimelineEvents ──

    it('getTimelineEvents calls /vulns/events with start and end ms', async () => {
        apiClient.get.mockResolvedValueOnce({ data: [] })

        await vulnService.getTimelineEvents('conn-1', 1700000000000, 1700086400000)

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/events', {
            params: {
                connection_id: 'conn-1',
                start_ms: 1700000000000,
                end_ms: 1700086400000
            }
        })
    })
})
