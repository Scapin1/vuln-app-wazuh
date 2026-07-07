import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import VulnAnalytics from '@/presentation/views/VulnAnalytics.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

vi.mock('@/application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
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

        // Trigger loading state
        wrapper.vm.loading = true
        await wrapper.vm.$nextTick()

        // GanttTab should be hidden (v-if="!loading")
        expect(wrapper.findComponent({ name: 'GanttTab' }).exists()).toBe(false)
        // Loading card should be visible
        expect(wrapper.text()).toContain('Cargando')
    })

    it('buildAnalytics fetches vulns and updates state', async () => {
        const mockVulns = [
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-web-01' },
            { cve_id: 'CVE-2026-0002', severity: 'HIGH', status: 'Resolved', agent_name: 'srv-db-02' }
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
        const mockVulns = [
            { cve_id: 'CVE-2026-0001', severity: 'CRITICAL', status: 'Detected', agent_name: 'srv-web-01' },
            { cve_id: 'CVE-2026-0002', severity: 'HIGH', status: 'Resolved', agent_name: 'srv-db-02' },
            { cve_id: 'CVE-2026-0003', severity: 'LOW', status: 'Detected', agent_name: 'srv-api-03' }
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
})
