import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import VulnAnalytics from '@/presentation/views/VulnAnalytics.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'
import { useVulnStore } from '@/application/stores/vulnStore'

vi.mock('@/application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
        syncVulns: vi.fn(),
        getFilterOptions: vi.fn(),
        getDashboardSummary: vi.fn(),
        getTimeline: vi.fn(),
        getAnalytics: vi.fn(),
        getTimelineEvents: vi.fn()
    }
}))

vi.mock('@/application/services/wazuhService', () => ({
    default: {
        getConnections: vi.fn()
    }
}))

describe('VulnAnalytics.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        wazuhService.getConnections.mockResolvedValue({ data: [] })
        vulnService.getVulns.mockResolvedValue({ data: [] })
    })

    it('loads connections on mount', async () => {
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 1, name: 'Conn A' }]
        })
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        expect(wazuhService.getConnections).toHaveBeenCalled()
        expect(wrapper.vm.connections).toEqual([{ id: 1, name: 'Conn A' }])
    })

    it('renders with empty data when no build is performed', async () => {
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        // No DEMO data — empty state
        expect(wrapper.vm.severityDistribution).toEqual({
            CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0
        })
        expect(wrapper.vm.statusDistribution).toEqual({
            Activo: 0, Resuelto: 0, Reabierto: 0
        })
        expect(wrapper.vm.topAgentsDistribution).toEqual([])
        expect(wrapper.vm.criticalCount).toBe(0)
    })

    it('shows loading card and hides GanttTab when loading', async () => {
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        // Trigger loading state (clear stale auto-load message)
        wrapper.vm.loadingMessage = ''
        wrapper.vm.loading = true
        await wrapper.vm.$nextTick()

        // GanttTab should be hidden (v-if="!loading")
        expect(wrapper.findComponent({ name: 'GanttTab' }).exists()).toBe(false)
        // Loading card should be visible
        expect(wrapper.find('.loading-card').exists()).toBe(true)
        expect(wrapper.text()).toContain('Cargando')
    })

    it('buildAnalytics fetches vulns and updates state', async () => {
        const recentDate = new Date()
        recentDate.setDate(recentDate.getDate() - 1)
        const mockVulns = [
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-web-01',
              last_seen: recentDate.toISOString() },
            { cve_id: 'CVE-2026-0002', severity: 'HIGH', status: 'Resolved', agent_name: 'srv-db-02',
              last_seen: recentDate.toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        // State should not be loading
        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(true)
        // Should have data
        expect(wrapper.vm.filteredVulnsData.length).toBe(2)
    })

    it('severity filter reduces data shown', async () => {
        const recentDate = new Date()
        recentDate.setDate(recentDate.getDate() - 1)
        const mockVulns = [
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-web-01',
              last_seen: recentDate.toISOString() },
            { cve_id: 'CVE-2026-0002', severity: 'HIGH', status: 'Resolved', agent_name: 'srv-db-02',
              last_seen: recentDate.toISOString() },
            { cve_id: 'CVE-2026-0003', severity: 'LOW', status: 'Detected', agent_name: 'srv-api-03',
              last_seen: recentDate.toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        // All 3 vulns
        expect(wrapper.vm.ganttData.length).toBe(3)

        // Filter by CRITICAL only
        wrapper.vm.selectedSeverities = ['CRITICAL']
        await wrapper.vm.$nextTick()

        // Should only show CRITICAL vulns
        expect(wrapper.vm.ganttData.length).toBe(1)
        expect(wrapper.vm.ganttData[0].severity).toBe('CRITICAL')

        // Clear filter
        wrapper.vm.selectedSeverities = []
        await wrapper.vm.$nextTick()

        // Back to all
        expect(wrapper.vm.ganttData.length).toBe(3)
    })

    it('renders TimelineFilters and GanttTab components', async () => {
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        expect(wrapper.findComponent({ name: 'TimelineFilters' }).exists()).toBe(true)
    })

    it('shows error banner when buildAnalytics fails', async () => {
        vulnService.getVulns.mockRejectedValue(new Error('Network error'))
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        expect(wrapper.vm.errorBanner).toContain('Error')
        expect(wrapper.find('.status-banner').exists()).toBe(true)
    })

    it('topCriticalCve returns most frequent CVE among critical vulns', async () => {
        const mockVulns = [
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-b',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2026-0002', severity: 'HIGH', status: 'Detected', agent_name: 'srv-c',
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.topCriticalCve).toBe('CVE-2026-0001')
    })

    it('topCriticalCve returns null when no critical vulns', () => {
        const wrapper = mount(VulnAnalytics)

        expect(wrapper.vm.topCriticalCve).toBeNull()
    })

    it('statusDistribution maps API status using STATUS_API_MAP', async () => {
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2', severity: 'HIGH', status: 'Resolved', agent_name: 'srv-b',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-3', severity: 'MEDIUM', status: 'Re-emerged', agent_name: 'srv-c',
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.statusDistribution).toEqual({
            Activo: 1, Resuelto: 1, Reabierto: 1
        })
    })

    it('statusDistribution handles null/unknown status', async () => {
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: null, agent_name: 'srv-a',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2', severity: 'HIGH', status: 'UnknownStatus', agent_name: 'srv-b',
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        // null/unknown status should not be counted
        expect(wrapper.vm.statusDistribution.Activo).toBe(0)
        expect(wrapper.vm.statusDistribution.Resuelto).toBe(0)
        expect(wrapper.vm.statusDistribution.Reabierto).toBe(0)
    })

    it('topAgentsDistribution aggregates and sorts agent counts', async () => {
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2', severity: 'HIGH', status: 'Detected', agent_name: 'srv-b',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-3', severity: 'MEDIUM', status: 'Detected', agent_name: 'srv-a',
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.topAgentsDistribution[0]).toEqual({ agent: 'srv-a', count: 2 })
        expect(wrapper.vm.topAgentsDistribution[1]).toEqual({ agent: 'srv-b', count: 1 })
    })

    it('topAgentsDistribution handles missing agent_name', async () => {
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: 'Detected', agent_name: null,
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.topAgentsDistribution[0].agent).toBe('unknown')
    })

    it('cancelBuild stops loading and clears state', () => {
        const wrapper = mount(VulnAnalytics)

        wrapper.vm.loading = true
        wrapper.vm.loadingMessage = 'Fetching...'
        wrapper.vm.fetchProgress = { current: 5 }

        wrapper.vm.cancelBuild()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.loadingMessage).toBe('Operación cancelada')
        expect(wrapper.vm.fetchProgress.current).toBe(0)
    })

    it('loadingBarWidth is 100 when done', () => {
        const wrapper = mount(VulnAnalytics)

        wrapper.vm.fetchProgress = { done: true }
        expect(wrapper.vm.loadingBarWidth).toBe(100)
    })

    it('loadingBarWidth caps at 80 for progress', () => {
        const wrapper = mount(VulnAnalytics)

        wrapper.vm.fetchProgress = { current: 100 }
        expect(wrapper.vm.loadingBarWidth).toBe(80)
    })

    it('loadingBarWidth scales with current progress', () => {
        const wrapper = mount(VulnAnalytics)

        wrapper.vm.fetchProgress = { current: 2 }
        expect(wrapper.vm.loadingBarWidth).toBe(40)
    })

    it('criticalCount counts only CRITICAL severity vulns', async () => {
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: new Date().toISOString() },
            { cve_id: 'CVE-2', severity: 'HIGH', status: 'Detected', agent_name: 'srv-b',
              last_seen: new Date().toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.criticalCount).toBe(1)
    })

    it('buildAnalytics filters by selected agents', async () => {
        const recentDate = new Date()
        const mockVulns = [
            { cve_id: 'CVE-1', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: recentDate.toISOString() },
            { cve_id: 'CVE-2', severity: 'HIGH', status: 'Detected', agent_name: 'srv-b',
              last_seen: recentDate.toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedAgents = ['srv-a']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.filteredVulnsData.length).toBe(1)
        expect(wrapper.vm.filteredVulnsData[0].agent_name).toBe('srv-a')
    })

    it('buildAnalytics filters by selected CVEs', async () => {
        const recentDate = new Date()
        const mockVulns = [
            { cve_id: 'CVE-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-a',
              last_seen: recentDate.toISOString() },
            { cve_id: 'CVE-0002', severity: 'HIGH', status: 'Detected', agent_name: 'srv-b',
              last_seen: recentDate.toISOString() }
        ]
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.selectedVulns = ['CVE-0001']
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.filteredVulnsData.length).toBe(1)
        expect(wrapper.vm.filteredVulnsData[0].cve_id).toBe('CVE-0001')
    })

    it('onConnectionChange resets filters and reloads data', async () => {
        vulnService.getVulns.mockResolvedValue({ data: [] })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        // Setup initial state
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.selectedAgents = ['srv-a']
        wrapper.vm.selectedVulns = ['CVE-1']

        await wrapper.vm.onConnectionChange()
        await flushPromises()

        expect(wrapper.vm.selectedAgents).toEqual([])
        expect(wrapper.vm.selectedVulns).toEqual([])
    })

    it('cleans up timer on unmount', async () => {
        const clearIntervalSpy = vi.spyOn(global, 'clearInterval')

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.unmount()

        expect(clearIntervalSpy).toHaveBeenCalled()
    })

    it('error banner renders when errorBanner has value', async () => {
        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        wrapper.vm.errorBanner = 'Custom error message'
        await wrapper.vm.$nextTick()

        const banner = wrapper.find('.status-banner')
        expect(banner.exists()).toBe(true)
        expect(banner.text()).toContain('Custom error message')
    })

    it('buildAnalytics handles error from store', async () => {
        vulnService.getVulns.mockRejectedValue(new Error('API failure'))
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(VulnAnalytics)
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(false)
        expect(wrapper.vm.errorBanner).toBeTruthy()
    })

    describe('sync button', () => {
        it('renders sync button in header-actions', async () => {
            const wrapper = mount(VulnAnalytics)
            await flushPromises()

            const button = wrapper.find('.header-actions button')
            expect(button.exists()).toBe(true)
            expect(button.text()).toContain('Forzar Sincronización')
        })

        it('calls syncVulns, invalidateCache, and buildAnalytics when clicked', async () => {
            vulnService.syncVulns.mockResolvedValue({})
            vulnService.getVulns.mockResolvedValue({ data: [] })
            wazuhService.getConnections.mockResolvedValue({
                data: [{ id: 'conn-1', name: 'Conn A' }]
            })

            const store = useVulnStore()
            const invalidateCacheSpy = vi.spyOn(store, 'invalidateCache')
            const wrapper = mount(VulnAnalytics)
            await flushPromises()

            const button = wrapper.find('.header-actions button')
            await button.trigger('click')
            await flushPromises()

            expect(vulnService.syncVulns).toHaveBeenCalledTimes(1)
            expect(invalidateCacheSpy).toHaveBeenCalledTimes(1)
            expect(wrapper.vm.hasBuilt).toBe(true)
        })

        it('disables sync button while syncing', async () => {
            let resolveSync
            vulnService.syncVulns.mockImplementation(() => new Promise(resolve => { resolveSync = resolve }))
            vulnService.getVulns.mockResolvedValue({ data: [] })
            wazuhService.getConnections.mockResolvedValue({ data: [{ id: 'conn-1', name: 'Conn A' }] })

            const wrapper = mount(VulnAnalytics)
            await flushPromises()

            const button = wrapper.find('.header-actions button')
            const clickPromise = button.trigger('click')
            await wrapper.vm.$nextTick()

            expect(wrapper.vm.syncing).toBe(true)
            expect(button.attributes('disabled')).toBeDefined()

            resolveSync()
            await clickPromise
            await flushPromises()

            expect(wrapper.vm.syncing).toBe(false)
        })

        it('shows error banner when sync fails', async () => {
            vulnService.syncVulns.mockRejectedValue(new Error('Sync failed'))
            wazuhService.getConnections.mockResolvedValue({ data: [{ id: 'conn-1', name: 'Conn A' }] })

            const wrapper = mount(VulnAnalytics)
            await flushPromises()

            const button = wrapper.find('.header-actions button')
            await button.trigger('click')
            await flushPromises()

            expect(wrapper.vm.errorBanner).toContain('Error durante la sincronización')
            expect(wrapper.vm.syncing).toBe(false)
        })

        it('does not call syncVulns when no connection is selected', async () => {
            vulnService.syncVulns.mockResolvedValue({})
            wazuhService.getConnections.mockResolvedValue({ data: [] })

            const wrapper = mount(VulnAnalytics)
            await flushPromises()

            expect(wrapper.vm.selectedConnection).toBe('')

            const button = wrapper.find('.header-actions button')
            await button.trigger('click')
            await flushPromises()

            expect(vulnService.syncVulns).not.toHaveBeenCalled()
        })
    })
})
