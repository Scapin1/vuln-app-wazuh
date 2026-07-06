import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '@/presentation/views/Dashboard.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

vi.mock('@/application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
        syncVulns: vi.fn()
    }
}))

vi.mock('@/application/services/wazuhService', () => ({
    default: {
        getConnections: vi.fn()
    }
}))

describe('Dashboard.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        wazuhService.getConnections.mockResolvedValue({ data: [] })
    })

    it('loads connections on mount', async () => {
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 1, name: 'Conn A' }]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wazuhService.getConnections).toHaveBeenCalled()
        expect(wrapper.vm.connections).toEqual([{ id: 1, name: 'Conn A' }])
    })

    it('renders initial state without fetching vulns on mount', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(false)
        expect(wrapper.text()).toContain('Sistema de Seguimiento de Vulnerabilidades')
        expect(vulnService.getVulns).not.toHaveBeenCalled()
    })

    it('buildDashboard fetching with pagination', async () => {
        vulnService.getVulns.mockResolvedValue({ data: [] })
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        expect(vulnService.getVulns).toHaveBeenCalledWith(
            expect.objectContaining({ connectionId: 'conn-1' }),
            expect.any(Object)
        )
        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(true)
        expect(wrapper.vm.dashboardData).toEqual([])
    })

    it('sets error when buildDashboard fails', async () => {
        vulnService.getVulns.mockRejectedValue(new Error('Network error'))
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        expect(wrapper.vm.error).toBe('Error al cargar vulnerabilidades. Verifica tu conexión Wazuh.')
        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(false)
    })

    it('syncs vulns and rebuilds dashboard', async () => {
        vulnService.getVulns.mockResolvedValue({ data: [] })
        vulnService.syncVulns.mockResolvedValue({})
        wazuhService.getConnections.mockResolvedValue({
            data: [{ id: 'conn-1', name: 'Conn A' }]
        })

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()
        expect(vulnService.getVulns).toHaveBeenCalled()

        // Reset and test sync
        vi.clearAllMocks()
        vulnService.getVulns.mockResolvedValue({ data: [] })
        vulnService.syncVulns.mockResolvedValue({})
        wazuhService.getConnections.mockResolvedValue({ data: [] })

        await wrapper.vm.syncVulns()
        await flushPromises()

        expect(wrapper.vm.syncing).toBe(false)
        expect(vulnService.syncVulns).toHaveBeenCalledTimes(1)
        expect(vulnService.getVulns).toHaveBeenCalled()
    })

    it('shows error when sync fails', async () => {
        vulnService.syncVulns.mockRejectedValue(new Error('Sync error'))

        const wrapper = mount(Dashboard)
        await flushPromises()

        await wrapper.vm.syncVulns()
        await flushPromises()

        expect(wrapper.vm.syncing).toBe(false)
        expect(wrapper.vm.error).toContain('Error durante la sincronización')
    })

    it('filters vulnerabilities by selected agent', async () => {
        vulnService.getVulns.mockResolvedValue({
            data: [
                { id: 1, connection_id: 'conn-1', severity: 'critical', cve_id: 'CVE-1', agent_name: 'Agent-1', status: 'Detected' },
                { id: 2, connection_id: 'conn-1', severity: 'low', cve_id: 'CVE-2', agent_name: 'Agent-2', status: 'Resolved' }
            ]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        wrapper.vm.selectedAgents = ['Agent-1']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.filteredVulns.length).toBe(1)
        expect(wrapper.vm.filteredVulns[0].agent_name).toBe('Agent-1')
    })

    it('filters vulnerabilities by selected severity', async () => {
        vulnService.getVulns.mockResolvedValue({
            data: [
                { id: 1, connection_id: 'conn-1', severity: 'critical', cve_id: 'CVE-1', agent_name: 'Agent-1', status: 'Detected' },
                { id: 2, connection_id: 'conn-1', severity: 'low', cve_id: 'CVE-2', agent_name: 'Agent-2', status: 'Resolved' }
            ]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        wrapper.vm.selectedSeverities = ['CRITICAL']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.filteredVulns.length).toBe(1)
        expect(wrapper.vm.filteredVulns[0].severity).toBe('critical')
    })

    it('filters vulnerabilities by selected cve', async () => {
        vulnService.getVulns.mockResolvedValue({
            data: [
                { id: 1, connection_id: 'conn-1', severity: 'critical', cve_id: 'CVE-2023-1234', agent_name: 'Agent-1', status: 'Detected' },
                { id: 2, connection_id: 'conn-1', severity: 'low', cve_id: 'CVE-2022-0001', agent_name: 'Agent-2', status: 'Resolved' }
            ]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        wrapper.vm.selectedVulns = ['CVE-2023-1234']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.filteredVulns.length).toBe(1)
        expect(wrapper.vm.filteredVulns[0].cve_id).toBe('CVE-2023-1234')
    })

    it('clears dependent filters on connection change', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedAgents = ['Agent-1']
        wrapper.vm.selectedVulns = ['CVE-2023-1234']
        wrapper.vm.selectedSeverities = ['CRITICAL']
        wrapper.vm.agentOptions = ['Agent-1']
        wrapper.vm.vulnOptions = ['CVE-2023-1234']
        wrapper.vm.severityOptions = ['CRITICAL']

        wrapper.vm.onConnectionChange()
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.selectedAgents).toEqual([])
        expect(wrapper.vm.selectedVulns).toEqual([])
        expect(wrapper.vm.selectedSeverities).toEqual([])
        expect(wrapper.vm.agentOptions).toEqual([])
        expect(wrapper.vm.vulnOptions).toEqual([])
        expect(wrapper.vm.severityOptions).toEqual([])
    })

    it('handles connection load error gracefully', async () => {
        wazuhService.getConnections.mockRejectedValue(new Error('Network error'))

        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.connections).toEqual([])
    })

    it('period chip selector works', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.period).toBe('30d')
        expect(wrapper.vm.periods).toHaveLength(5)

        wrapper.vm.period = '24h'
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.period).toBe('24h')
    })

    it('updates filter options after building', async () => {
        vulnService.getVulns.mockResolvedValue({
            data: [
                { agent_name: 'Agent-1', cve_id: 'CVE-1', severity: 'critical', connection_id: 'conn-1' },
                { agent_name: 'Agent-2', cve_id: 'CVE-2', severity: 'low', connection_id: 'conn-1' }
            ]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        expect(wrapper.vm.agentOptions).toContain('Agent-1')
        expect(wrapper.vm.agentOptions).toContain('Agent-2')
        expect(wrapper.vm.vulnOptions).toContain('CVE-1')
        expect(wrapper.vm.vulnOptions).toContain('CVE-2')
    })

    it('extracts unique severity options sorted by level', async () => {
        vulnService.getVulns.mockResolvedValue({
            data: [
                { agent_name: 'A1', cve_id: 'CVE-1', severity: 'low', connection_id: 'conn-1' },
                { agent_name: 'A2', cve_id: 'CVE-2', severity: 'critical', connection_id: 'conn-1' },
                { agent_name: 'A3', cve_id: 'CVE-3', severity: 'high', connection_id: 'conn-1' }
            ]
        })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        await wrapper.vm.buildDashboard()
        await flushPromises()

        expect(wrapper.vm.severityOptions[0]).toBe('CRITICAL')
        expect(wrapper.vm.severityOptions[1]).toBe('HIGH')
        expect(wrapper.vm.severityOptions[2]).toBe('LOW')
    })

    it('dropdown open/close with activeDropdown', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Set up options so dropdowns are enabled
        wrapper.vm.agentOptions = ['Agent-1']
        wrapper.vm.vulnOptions = ['CVE-1']
        wrapper.vm.severityOptions = ['CRITICAL']

        expect(wrapper.vm.activeDropdown).toBe('')
        wrapper.vm.activeDropdown = 'agents'
        expect(wrapper.vm.activeDropdown).toBe('agents')
        wrapper.vm.activeDropdown = 'vulns'
        expect(wrapper.vm.activeDropdown).toBe('vulns')
        wrapper.vm.activeDropdown = 'severity'
        expect(wrapper.vm.activeDropdown).toBe('severity')
        wrapper.vm.activeDropdown = ''
        expect(wrapper.vm.activeDropdown).toBe('')
    })

    it('dropdown search for agents and CVEs', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.agentOptions = ['Agent-1', 'Agent-2']
        wrapper.vm.vulnOptions = ['CVE-1', 'CVE-2']

        wrapper.vm.search.agent = 'Agent-1'
        expect(wrapper.vm.filteredAgents.length).toBe(1)

        wrapper.vm.search.vuln = 'CVE-2'
        expect(wrapper.vm.filteredCVEOptions.length).toBe(1)
    })

    it('does not fetch vulns on mount without connection', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.selectedConnection).toBe('')
        expect(vulnService.getVulns).not.toHaveBeenCalled()
        expect(wrapper.vm.hasBuilt).toBe(false)
    })

    it('does not build without selectedConnection', async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()

        await wrapper.vm.buildDashboard()
        expect(vulnService.getVulns).not.toHaveBeenCalled()
    })

    it('buildDashboard sets loading correctly throughout the flow', async () => {
        // Use a deferred promise to control timing
        let resolveBuild
        const buildPromise = new Promise(resolve => { resolveBuild = resolve })
        vulnService.getVulns.mockImplementation(() => buildPromise)

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 'conn-1'
        wrapper.vm.buildDashboard()
        await wrapper.vm.$nextTick()

        // loading should be true while build is in progress
        expect(wrapper.vm.loading).toBe(true)

        // Resolve the build
        resolveBuild({ data: [] })
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.hasBuilt).toBe(true)
    })

    describe('getSeverityLevel utility function', () => {
        it('returns 0 for null/undefined', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()
            expect(wrapper.vm.getSeverityLevel(null)).toBe(0)
            expect(wrapper.vm.getSeverityLevel(undefined)).toBe(0)
            expect(wrapper.vm.getSeverityLevel('')).toBe(0)
        })

        it('returns 4 for critical', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()
            expect(wrapper.vm.getSeverityLevel('critical')).toBe(4)
            expect(wrapper.vm.getSeverityLevel('critica')).toBe(4)
        })

        it('returns 3 for high', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()
            expect(wrapper.vm.getSeverityLevel('high')).toBe(3)
            expect(wrapper.vm.getSeverityLevel('alta')).toBe(3)
        })

        it('returns 2 for medium', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()
            expect(wrapper.vm.getSeverityLevel('medium')).toBe(2)
            expect(wrapper.vm.getSeverityLevel('media')).toBe(2)
        })

        it('returns 1 for low and unknown', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()
            expect(wrapper.vm.getSeverityLevel('low')).toBe(1)
            expect(wrapper.vm.getSeverityLevel('unknown')).toBe(1)
        })
    })

    describe('getSeverityBadgeClass', () => {
        it('returns correct badge classes', async () => {
            const wrapper = mount(Dashboard)
            await flushPromises()

            expect(wrapper.vm.getSeverityBadgeClass('critical')).toBe('badge-critical')
            expect(wrapper.vm.getSeverityBadgeClass('critica')).toBe('badge-critical')
            expect(wrapper.vm.getSeverityBadgeClass('high')).toBe('badge-high')
            expect(wrapper.vm.getSeverityBadgeClass('alta')).toBe('badge-high')
            expect(wrapper.vm.getSeverityBadgeClass('medium')).toBe('badge-medium')
            expect(wrapper.vm.getSeverityBadgeClass('media')).toBe('badge-medium')
            expect(wrapper.vm.getSeverityBadgeClass('low')).toBe('badge-low')
        })
    })

    describe('updateFilterOptions', () => {
        it('handles missing fields gracefully', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { agent_name: null, cve_id: 'CVE-1', severity: 'critical', connection_id: 'conn-1' },
                    { agent_name: 'Agent-2', cve_id: undefined, severity: 'low', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            expect(wrapper.vm.agentOptions).toEqual(['Agent-2'])
            expect(wrapper.vm.vulnOptions).toEqual(['CVE-1'])
            expect(wrapper.vm.severityOptions).toContain('CRITICAL')
            expect(wrapper.vm.severityOptions).toContain('LOW')
        })
    })

    describe('Severity chart integration', () => {
        it('computes severityDistribution from filteredVulns', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { severity: 'critical', status: 'Detected', agent_name: 'A1', cve_id: 'C-1', connection_id: 'conn-1' },
                    { severity: 'low', status: 'Resolved', agent_name: 'A2', cve_id: 'C-2', connection_id: 'conn-1' },
                    { severity: 'critical', status: 'Detected', agent_name: 'A3', cve_id: 'C-3', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            expect(wrapper.vm.severityDistribution).toEqual({
                CRITICAL: 2,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 1
            })
        })

        it('updates severityDistribution when filters change', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { severity: 'critical', status: 'Detected', agent_name: 'A1', cve_id: 'C-1', connection_id: 'conn-1' },
                    { severity: 'low', status: 'Resolved', agent_name: 'A2', cve_id: 'C-2', connection_id: 'conn-1' },
                    { severity: 'critical', status: 'Detected', agent_name: 'A3', cve_id: 'C-3', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            expect(wrapper.vm.severityDistribution.CRITICAL).toBe(2)

            wrapper.vm.selectedSeverities = ['CRITICAL']
            await wrapper.vm.$nextTick()

            expect(wrapper.vm.severityDistribution).toEqual({
                CRITICAL: 2,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0
            })
        })

        it('computes statusDistribution from dashboardData (unfiltered)', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { severity: 'critical', status: 'Detected', agent_name: 'A1', cve_id: 'C-1', connection_id: 'conn-1' },
                    { severity: 'low', status: 'Resolved', agent_name: 'A2', cve_id: 'C-2', connection_id: 'conn-1' },
                    { severity: 'medium', status: 'Re-emerged', agent_name: 'A3', cve_id: 'C-3', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            expect(wrapper.vm.statusDistribution).toEqual({
                Detected: 1,
                Resolved: 1,
                'Re-emerged': 1
            })
        })

        it('statusDistribution stays on dashboardData even when filters are active', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { severity: 'critical', status: 'Detected', agent_name: 'A1', cve_id: 'C-1', connection_id: 'conn-1' },
                    { severity: 'low', status: 'Resolved', agent_name: 'A2', cve_id: 'C-2', connection_id: 'conn-1' },
                    { severity: 'critical', status: 'Detected', agent_name: 'A3', cve_id: 'C-3', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            wrapper.vm.selectedSeverities = ['CRITICAL']
            await wrapper.vm.$nextTick()

            expect(wrapper.vm.filteredVulns.length).toBe(2)
            expect(wrapper.vm.statusDistribution).toEqual({
                Detected: 2,
                Resolved: 1,
                'Re-emerged': 0
            })
        })

        it('renders chart titles in template', async () => {
            vulnService.getVulns.mockResolvedValue({
                data: [
                    { severity: 'critical', status: 'Detected', agent_name: 'A1', cve_id: 'C-1', connection_id: 'conn-1' },
                    { severity: 'low', status: 'Resolved', agent_name: 'A2', cve_id: 'C-2', connection_id: 'conn-1' }
                ]
            })
            const wrapper = mount(Dashboard)
            await flushPromises()

            wrapper.vm.selectedConnection = 'conn-1'
            await wrapper.vm.buildDashboard()
            await flushPromises()

            expect(wrapper.text()).toContain('Vulnerabilidades por Severidad')
            expect(wrapper.text()).toContain('Estado de Vulnerabilidades')
        })
    })
})
