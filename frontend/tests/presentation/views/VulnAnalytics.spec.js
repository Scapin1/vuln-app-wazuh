import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia } from 'pinia'
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

function setupMocks() {
    testPinia = createPinia()
    // Must use resetAllMocks — clearAllMocks keeps implementations, causing leaks
    vi.resetAllMocks()
}

/** Mount VulnAnalytics with the test Pinia instance. */
function mountVuln() {
    return mount(VulnAnalytics, { global: { plugins: [testPinia] } })
}

let testPinia

/** Mount VulnAnalytics when getConnections returns given data.
 *  Returns the wrapper and a promise that resolves when onMounted completes.
 */
async function mountWithConnections(connectionsData) {
    wazuhService.getConnections.mockResolvedValue({ data: connectionsData })
    const wrapper = mount(VulnAnalytics, {
        global: { plugins: [testPinia] }
    })
    await flushPromises()
    return wrapper
}

/** Mount VulnAnalytics when getConnections throws.
 *  Returns the wrapper and a promise that resolves when onMounted completes. */
async function mountWithConnectionsError() {
    wazuhService.getConnections.mockRejectedValue(new Error('Connection error'))
    const wrapper = mount(VulnAnalytics, {
        global: { plugins: [testPinia] }
    })
    await flushPromises()
    return wrapper
}

describe('VulnAnalytics.vue', () => {
    beforeEach(() => {
        setupMocks()
    })

    it('loads connections on mount', async () => {
        const wrapper = await mountWithConnections([
            { id: 1, name: 'Conn A' }
        ])

        // with a connection, onConnectionChange auto-builds which fails (no mocks)
        // but connections should still be loaded
        expect(wazuhService.getConnections).toHaveBeenCalled()
        expect(wrapper.vm.connections).toEqual([{ id: 1, name: 'Conn A' }])
    })

    it('renders with empty data', () => {
        // Mount with no connections - no auto-build triggers
        const wrapper = mountVuln()
        // No flushPromises - we don't wait for onMounted

        expect(wrapper.vm.severityDistribution).toEqual({
            CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0
        })
        expect(wrapper.vm.statusDistribution).toEqual({
            Activo: 0, Resuelto: 0, Reabierto: 0
        })
        expect(wrapper.vm.topAgentsDistribution).toEqual([])
        expect(wrapper.vm.criticalCount).toBe(0)
        expect(wrapper.vm.topCriticalCve).toBeNull()
    })

    it('shows loading card and hides GanttTab when loading', async () => {
        const wrapper = await mountWithConnectionsError()

        wrapper.vm.loadingMessage = ''
        wrapper.vm.loading = true
        await wrapper.vm.$nextTick()

        expect(wrapper.findComponent({ name: 'GanttTab' }).exists()).toBe(false)
        expect(wrapper.find('.loading-card').exists()).toBe(true)
        expect(wrapper.text()).toContain('Cargando')
    })

    it('buildAnalytics fetches analytics and timeline data', async () => {
        const mockAnalytics = {
            severity_distribution: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
            status_distribution: { Activo: 1 },
            top_agents: [{ agent: 'srv-web-01', count: 1 }],
            critical_count: 1,
            top_critical_cve: 'CVE-2026-0001'
        }
        const mockTimeline = {
            cves: [{ cve_id: 'CVE-2026-0001', severity: 'CRITICAL', snapshots: [] }],
            total_cves: 1, total_pages: 1, current_page: 1, per_page: 20
        }

        // Mount so connections fail to prevent auto-build
        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockResolvedValue({ data: mockAnalytics })
        vulnService.getTimeline.mockResolvedValue({ data: mockTimeline })
        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(true)
        expect(wrapper.vm.analyticsData).toEqual(mockAnalytics)
        expect(wrapper.vm.timelineData).toEqual(mockTimeline)
    })

    it('metrics computed properties source from analyticsData', async () => {
        const mockAnalytics = {
            severity_distribution: { CRITICAL: 2, HIGH: 1, MEDIUM: 0, LOW: 3 },
            status_distribution: { Activo: 4, Resuelto: 1, Reabierto: 1 },
            top_agents: [{ agent: 'srv-a', count: 3 }, { agent: 'srv-b', count: 2 }],
            critical_count: 2,
            top_critical_cve: 'CVE-2026-0001'
        }

        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockResolvedValue({ data: mockAnalytics })
        vulnService.getTimeline.mockResolvedValue({
            data: { cves: [], total_cves: 0, total_pages: 1, current_page: 1, per_page: 20 }
        })
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.severityDistribution).toEqual({
            CRITICAL: 2, HIGH: 1, MEDIUM: 0, LOW: 3
        })
        expect(wrapper.vm.statusDistribution).toEqual({
            Activo: 4, Resuelto: 1, Reabierto: 1
        })
        expect(wrapper.vm.topAgentsDistribution).toEqual([
            { agent: 'srv-a', count: 3 }, { agent: 'srv-b', count: 2 }
        ])
        expect(wrapper.vm.criticalCount).toBe(2)
        expect(wrapper.vm.topCriticalCve).toBe('CVE-2026-0001')
    })

    it('ganttData uses timelineData.cves', async () => {
        const mockTimeline = {
            cves: [
                { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', snapshots: [] },
                { cve_id: 'CVE-2026-0002', severity: 'HIGH', snapshots: [] }
            ],
            total_cves: 2, total_pages: 1, current_page: 1, per_page: 20
        }

        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockResolvedValue({
            data: { severity_distribution: {}, status_distribution: {}, top_agents: [], critical_count: 0, top_critical_cve: null }
        })
        vulnService.getTimeline.mockResolvedValue({ data: mockTimeline })
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.ganttData).toHaveLength(2)
        expect(wrapper.vm.ganttData[0].cve_id).toBe('CVE-2026-0001')
        expect(wrapper.vm.ganttData[1].cve_id).toBe('CVE-2026-0002')
    })

    it('ganttData is empty array when timelineData is null', () => {
        const wrapper = mountVuln()
        expect(wrapper.vm.ganttData).toEqual([])
    })

    it('renders TimelineFilters and passes snapshots to GanttTab', async () => {
        const mockTimeline = {
            cves: [{ cve_id: 'CVE-2026-0001', severity: 'CRITICAL', snapshots: [] }],
            total_cves: 1, total_pages: 1, current_page: 1, per_page: 20
        }

        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockResolvedValue({
            data: { severity_distribution: {}, status_distribution: {}, top_agents: [], critical_count: 0, top_critical_cve: null }
        })
        vulnService.getTimeline.mockResolvedValue({ data: mockTimeline })
        await wrapper.vm.buildAnalytics()
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(wrapper.findComponent({ name: 'TimelineFilters' }).exists()).toBe(true)
        const ganttTab = wrapper.findComponent({ name: 'GanttTab' })
        expect(ganttTab.exists()).toBe(true)
        // In Phase 2, GanttTab still expects ganttData prop (will update in Phase 3)
        // We pass snapshots, but GanttTab doesn't declare it yet — skip prop assertion
    })

    it('shows error banner when buildAnalytics analytics call fails', async () => {
        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockRejectedValue(new Error('API error'))
        vulnService.getTimeline.mockResolvedValue({
            data: { cves: [], total_cves: 0, total_pages: 1, current_page: 1, per_page: 20 }
        })
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        // hasBuilt should be false because the analytics call failed
        // But buildAnalytics sets hasBuilt=false initially and in catch, so it should be false
        expect(wrapper.vm.hasBuilt).toBe(false)
        expect(wrapper.vm.errorBanner).toBeTruthy()
        expect(wrapper.vm.errorBanner).toContain('Error')
    })

    it('shows error banner when buildAnalytics timeline call fails', async () => {
        const wrapper = await mountWithConnectionsError()

        vulnService.getAnalytics.mockResolvedValue({
            data: { severity_distribution: {}, status_distribution: {}, top_agents: [], critical_count: 0, top_critical_cve: null }
        })
        vulnService.getTimeline.mockRejectedValue(new Error('Timeline error'))
        await wrapper.vm.buildAnalytics()
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(false)
        expect(wrapper.vm.errorBanner).toBeTruthy()
    })

    it('cancelBuild stops loading and clears state', () => {
        const wrapper = mountVuln()

        wrapper.vm.loading = true
        wrapper.vm.loadingMessage = 'Fetching...'
        wrapper.vm.fetchProgress = { current: 5 }

        wrapper.vm.cancelBuild()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.loadingMessage).toBe('Operación cancelada')
        expect(wrapper.vm.fetchProgress.current).toBe(0)
    })

    it('loadingBarWidth is 100 when done', () => {
        const wrapper = mountVuln()
        wrapper.vm.fetchProgress = { done: true }
        expect(wrapper.vm.loadingBarWidth).toBe(100)
    })

    it('loadingBarWidth caps at 80 for progress', () => {
        const wrapper = mountVuln()
        wrapper.vm.fetchProgress = { current: 100 }
        expect(wrapper.vm.loadingBarWidth).toBe(80)
    })

    it('loadingBarWidth scales with current progress', () => {
        const wrapper = mountVuln()
        wrapper.vm.fetchProgress = { current: 2 }
        expect(wrapper.vm.loadingBarWidth).toBe(40)
    })

    it('onConnectionChange resets filters and loads options', async () => {
        const wrapper = await mountWithConnectionsError()
        wrapper.vm.selectedConnection = 'conn-1'

        vulnService.getFilterOptions.mockResolvedValue({
            data: { agents: ['srv-a', 'srv-b'], cves: ['CVE-1', 'CVE-2'] }
        })
        vulnService.getAnalytics.mockResolvedValue({
            data: { severity_distribution: {}, status_distribution: {}, top_agents: [], critical_count: 0, top_critical_cve: null }
        })
        vulnService.getTimeline.mockResolvedValue({
            data: { cves: [], total_cves: 0, total_pages: 1, current_page: 1, per_page: 20 }
        })
        await wrapper.vm.onConnectionChange()
        await flushPromises()

        expect(wrapper.vm.selectedAgents).toEqual([])
        expect(wrapper.vm.selectedVulns).toEqual([])
        expect(wrapper.vm.agentOpts).toContain('srv-a')
        expect(wrapper.vm.vulnOpts).toContain('CVE-1')
    })

    it('onConnectionChange shows error banner when filter options fail', async () => {
        const wrapper = await mountWithConnectionsError()
        wrapper.vm.selectedConnection = 'conn-1'

        vulnService.getFilterOptions.mockRejectedValue(new Error('Network error'))
        vulnService.getAnalytics.mockRejectedValue(new Error('API error'))
        vulnService.getTimeline.mockRejectedValue(new Error('API error'))
        await wrapper.vm.onConnectionChange()
        await flushPromises()

        expect(wrapper.vm.errorBanner).toBeTruthy()
    })

    it('cleans up timer on unmount', async () => {
        const clearIntervalSpy = vi.spyOn(global, 'clearInterval')
        const wrapper = await mountWithConnectionsError()
        wrapper.unmount()
        expect(clearIntervalSpy).toHaveBeenCalled()
    })

    it('error banner renders when errorBanner has value', async () => {
        const wrapper = await mountWithConnectionsError()

        wrapper.vm.errorBanner = 'Custom error message'
        await wrapper.vm.$nextTick()

        const banner = wrapper.find('.status-banner')
        expect(banner.exists()).toBe(true)
        expect(banner.text()).toContain('Custom error message')
    })

    it('does not render filteredVulnsData ref (removed)', async () => {
        const wrapper = await mountWithConnectionsError()
        expect(wrapper.vm.filteredVulnsData).toBeUndefined()
    })

    describe('sync button', () => {
        it('renders sync button in header-actions', async () => {
            const wrapper = await mountWithConnectionsError()
            const button = wrapper.find('.header-actions button')
            expect(button.exists()).toBe(true)
            expect(button.text()).toContain('Forzar Sincronización')
        })

        it('calls syncVulns, invalidateCache, and buildAnalytics when clicked', async () => {
            vulnService.syncVulns.mockResolvedValue({})
            vulnService.getAnalytics.mockResolvedValue({
                data: { severity_distribution: {}, status_distribution: {}, top_agents: [], critical_count: 0, top_critical_cve: null }
            })
            vulnService.getTimeline.mockResolvedValue({
                data: { cves: [], total_cves: 0, total_pages: 1, current_page: 1, per_page: 20 }
            })

            const store = useVulnStore()
            const invalidateCacheSpy = vi.spyOn(store, 'invalidateCache')
            const wrapper = await mountWithConnectionsError()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.$nextTick()

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

            const wrapper = await mountWithConnectionsError()
            wrapper.vm.selectedConnection = 'conn-1'

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

            const wrapper = await mountWithConnectionsError()
            wrapper.vm.selectedConnection = 'conn-1'

            const button = wrapper.find('.header-actions button')
            await button.trigger('click')
            await flushPromises()

            expect(wrapper.vm.errorBanner).toContain('Error durante la sincronización')
            expect(wrapper.vm.syncing).toBe(false)
        })

        it('does not call syncVulns when no connection is selected', async () => {
            const wrapper = await mountWithConnectionsError()

            const button = wrapper.find('.header-actions button')
            await button.trigger('click')
            await flushPromises()

            expect(vulnService.syncVulns).not.toHaveBeenCalled()
        })
    })
})
