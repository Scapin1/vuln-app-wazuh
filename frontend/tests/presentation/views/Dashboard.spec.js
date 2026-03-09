import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '@/presentation/views/Dashboard.vue'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
        syncVulns: vi.fn()
    }
}))

describe('Dashboard.vue', () => {
    const mockVulns = [
        {
            id: 1,
            connection_name: 'Conn A',
            severity: 'critical',
            cve_id: 'CVE-2023-1234',
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: 'Agent-1',
            package_name: 'bash',
            package_version: '5.0'
        },
        {
            id: 2,
            connection_name: 'Conn B',
            severity: 'low',
            cve_id: 'CVE-2022-0001',
            first_seen: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: 'Agent-2',
            package_name: 'curl',
            package_version: '7.0'
        }
    ]

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders loading state initially and then shows vulns', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)

        // Check loading indicator (might be hard to grab if it disappears instantly, but initially loading is true)
        expect(wrapper.vm.loading).toBe(true)

        // Wait for API to resolve
        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(vulnService.getVulns).toHaveBeenCalledTimes(1)
        expect(wrapper.vm.vulns.length).toBe(2)

        // Check if table rendered with correct number of rows (excluding header)
        const rows = wrapper.findAll('tbody tr')
        expect(rows.length).toBe(2)
        // verify connection names rendered in first column
        expect(rows[0].text()).toContain('Conn A')
        expect(rows[1].text()).toContain('Conn B')
    })

    it('injects mock data when getVulns fails', async () => {
        vulnService.getVulns.mockRejectedValueOnce(new Error('Network error'))
        const wrapper = mount(Dashboard)

        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.error).toBe('')
    })

    it('syncs vulns correctly', async () => {
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        vulnService.syncVulns.mockResolvedValueOnce({})

        const wrapper = mount(Dashboard)
        await flushPromises() // Wait for initial fetch

        expect(vulnService.getVulns).toHaveBeenCalledTimes(1)

        // Trigger sync
        await wrapper.vm.syncVulns()

        expect(wrapper.vm.syncing).toBe(false)
        expect(vulnService.syncVulns).toHaveBeenCalledTimes(1)
        expect(vulnService.getVulns).toHaveBeenCalledTimes(2) // Fetches again after sync
    })

    it('shows error when sync fails', async () => {
        vulnService.getVulns.mockResolvedValue({ data: mockVulns })
        vulnService.syncVulns.mockRejectedValueOnce(new Error('Sync error'))

        const wrapper = mount(Dashboard)
        await flushPromises() // initial fetch

        await wrapper.vm.syncVulns()
        expect(wrapper.vm.syncing).toBe(false)
        expect(wrapper.vm.error).toContain('Error durante la sincronización')
    })

    it('toggles filters visibility', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.showFilters).toBe(false)

        // Find the button (Filtros)
        const filterBtn = wrapper.findAll('button').find(b => b.text().includes('Filtros') || b.text().includes('Ocultar'))
        await filterBtn.trigger('click')

        expect(wrapper.vm.showFilters).toBe(true)
    })

    it('filters vulnerabilities by text (agent name)', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.filters.agente = 'Agent-1'
        await wrapper.vm.$nextTick()

        // sortedVulns should filter based on text
        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].agent_name).toBe('Agent-1')
    })

    it('filters vulnerabilities by date', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Agent-2 is 48 hrs old
        const yesterday = new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString().split('T')[0]

        wrapper.vm.filters.endDate = yesterday
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].agent_name).toBe('Agent-2')
    })

    it('sorts vulnerabilities on header click', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Default sorting is last_seen desc
        expect(wrapper.vm.sortKey).toBe('last_seen')
        expect(wrapper.vm.sortOrder).toBe('desc')

        // Call sortBy explicitly for severity
        wrapper.vm.sortBy('severity')

        expect(wrapper.vm.sortKey).toBe('severity')
        expect(wrapper.vm.sortOrder).toBe('asc')

        // Click again to reverse
        wrapper.vm.sortBy('severity')
        expect(wrapper.vm.sortOrder).toBe('desc')

        // Click a third time to clear sorting
        wrapper.vm.sortBy('severity')
        expect(wrapper.vm.sortKey).toBe('')
    })

    it('clears filters correctly', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Set some filters
        wrapper.vm.filters.severidad = 'critical'
        wrapper.vm.filters.agente = 'Agent-1'
        wrapper.vm.filters.startDate = '2023-01-01'
        wrapper.vm.filters.endDate = '2023-12-31'

        wrapper.vm.clearFilters()

        expect(wrapper.vm.filters.severidad).toBe('')
        expect(wrapper.vm.filters.agente).toBe('')
        expect(wrapper.vm.filters.startDate).toBe('')
        expect(wrapper.vm.filters.endDate).toBe('')
    })

    it('filters vulnerabilities by severity', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.filters.severidad = 'critical'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].severity).toBe('critical')
    })

    it('filters vulnerabilities by CVE ID', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.filters.cveId = 'CVE-2023-1234'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].cve_id).toBe('CVE-2023-1234')
    })

    it('filters vulnerabilities by software package', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.filters.software = 'bash'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].package_name).toBe('bash')
    })

    it('handles empty vulnerability data', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: [] })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.vulns.length).toBe(0)
        expect(wrapper.vm.sortedVulns.length).toBe(0)
        expect(wrapper.vm.totalPages).toBe(0)
    })

    it('handles single page pagination correctly', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.totalPages).toBe(1)
        expect(wrapper.vm.currentPage).toBe(1)
        expect(wrapper.vm.paginatedVulns.length).toBe(2)
    })

    it('handles multiple pages correctly', async () => {
        // Create 60 mock vulnerabilities to exceed itemsPerPage (50)
        const manyVulns = Array.from({ length: 60 }, (_, i) => ({
            ...mockVulns[0],
            id: i + 1,
            cve_id: `CVE-2023-${i + 1000}`
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: manyVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.totalPages).toBe(2)
        expect(wrapper.vm.paginatedVulns.length).toBe(50) // First page

        // Go to next page
        wrapper.vm.nextPage()
        expect(wrapper.vm.currentPage).toBe(2)
        expect(wrapper.vm.paginatedVulns.length).toBe(10) // Second page
    })

    it('handles pagination navigation correctly', async () => {
        const manyVulns = Array.from({ length: 150 }, (_, i) => ({
            ...mockVulns[0],
            id: i + 1
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: manyVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.currentPage).toBe(1)

        // Test next/prev
        wrapper.vm.nextPage()
        expect(wrapper.vm.currentPage).toBe(2)

        wrapper.vm.prevPage()
        expect(wrapper.vm.currentPage).toBe(1)

        // Test jump forward/backward
        wrapper.vm.jumpForward()
        expect(wrapper.vm.currentPage).toBe(11) // pageJump = 10

        wrapper.vm.jumpBackward()
        expect(wrapper.vm.currentPage).toBe(1)

        // Test boundaries
        wrapper.vm.prevPage()
        expect(wrapper.vm.currentPage).toBe(1) // Should not go below 1

        wrapper.vm.currentPage = 3
        for (let i = 0; i < 10; i++) wrapper.vm.nextPage()
        expect(wrapper.vm.currentPage).toBe(3) // Should not exceed totalPages
    })

    it('resets to page 1 when filters change', async () => {
        const manyVulns = Array.from({ length: 100 }, (_, i) => ({
            ...mockVulns[0],
            id: i + 1
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: manyVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.currentPage = 2
        wrapper.vm.filters.agente = 'test'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.currentPage).toBe(1)
    })

    it('resets to page 1 when sort changes', async () => {
        const manyVulns = Array.from({ length: 100 }, (_, i) => ({
            ...mockVulns[0],
            id: i + 1
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: manyVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.currentPage = 2
        wrapper.vm.sortBy('severity')

        expect(wrapper.vm.currentPage).toBe(1)
    })

    it('sorts by different columns correctly', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Sort by connection_name ascending
        wrapper.vm.sortBy('connection_name')
        expect(wrapper.vm.sortKey).toBe('connection_name')
        expect(wrapper.vm.sortOrder).toBe('asc')
        expect(wrapper.vm.sortedVulns[0].connection_name).toBe('Conn A')
        expect(wrapper.vm.sortedVulns[1].connection_name).toBe('Conn B')

        // Sort by connection_name descending
        wrapper.vm.sortBy('connection_name')
        expect(wrapper.vm.sortOrder).toBe('desc')
        expect(wrapper.vm.sortedVulns[0].connection_name).toBe('Conn B')
        expect(wrapper.vm.sortedVulns[1].connection_name).toBe('Conn A')
    })

    it('sorts by severity with proper priority', async () => {
        const severityVulns = [
            { ...mockVulns[0], severity: 'low' },
            { ...mockVulns[1], severity: 'critical' },
            { ...mockVulns[0], severity: 'medium', id: 3 }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: severityVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.sortBy('severity')
        expect(wrapper.vm.sortedVulns[0].severity).toBe('critical')
        expect(wrapper.vm.sortedVulns[1].severity).toBe('medium')
        expect(wrapper.vm.sortedVulns[2].severity).toBe('low')
    })

    it('sorts by date fields correctly', async () => {
        const dateVulns = [
            { ...mockVulns[0], first_seen: '2023-01-01T00:00:00Z' },
            { ...mockVulns[1], first_seen: '2023-01-03T00:00:00Z' },
            { ...mockVulns[0], first_seen: '2023-01-02T00:00:00Z', id: 3 }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: dateVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.sortBy('first_seen')
        expect(wrapper.vm.sortedVulns[0].first_seen).toBe('2023-01-01T00:00:00Z')
        expect(wrapper.vm.sortedVulns[1].first_seen).toBe('2023-01-02T00:00:00Z')
        expect(wrapper.vm.sortedVulns[2].first_seen).toBe('2023-01-03T00:00:00Z')
    })

    it('handles complex filtering scenarios', async () => {
        const complexVulns = [
            { ...mockVulns[0], severity: 'critical', agent_name: 'web-server', cve_id: 'CVE-2023-0001' },
            { ...mockVulns[1], severity: 'high', agent_name: 'database', cve_id: 'CVE-2023-0002' },
            { ...mockVulns[0], severity: 'medium', agent_name: 'web-server', cve_id: 'CVE-2023-0003', id: 3 }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: complexVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Multiple filters
        wrapper.vm.filters.severidad = 'high'
        wrapper.vm.filters.agente = 'database'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].severity).toBe('high')
        expect(wrapper.vm.sortedVulns[0].agent_name).toBe('database')
    })

    it('handles date range filtering edge cases', async () => {
        const dateVulns = [
            { ...mockVulns[0], first_seen: '2023-06-01T00:00:00Z', last_seen: '2023-06-15T00:00:00Z' },
            { ...mockVulns[1], first_seen: '2023-07-01T00:00:00Z', last_seen: '2023-07-15T00:00:00Z' }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: dateVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Filter by date range
        wrapper.vm.filters.startDate = '2023-06-05'
        wrapper.vm.filters.endDate = '2023-06-20'
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].first_seen).toBe('2023-06-01T00:00:00Z')
    })

    it('computes severity options correctly', async () => {
        const severityVulns = [
            { ...mockVulns[0], severity: 'CRITICAL' },
            { ...mockVulns[1], severity: 'high' },
            { ...mockVulns[0], severity: 'Medium', id: 3 },
            { ...mockVulns[1], severity: 'LOW', id: 4 }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: severityVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        const options = wrapper.vm.severidadOptions
        expect(options).toContain('CRITICAL')
        expect(options).toContain('HIGH')
        expect(options).toContain('MEDIUM')
        expect(options).toContain('LOW')
        // Should be sorted by severity level (critical first)
        expect(options[0]).toBe('CRITICAL')
    })

    it('handles malformed data gracefully', async () => {
        const malformedVulns = [
            { ...mockVulns[0], severity: null, agent_name: undefined },
            { ...mockVulns[1], cve_id: '', package_name: null }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: malformedVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Should not crash and should handle null/undefined values
        expect(wrapper.vm.sortedVulns.length).toBe(2)
        expect(wrapper.vm.severidadOptions.length).toBeGreaterThan(0)
    })

    it('maintains filter state across operations', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        // Set filters
        wrapper.vm.filters.severidad = 'critical'
        wrapper.vm.filters.agente = 'Agent-1'

        // Change sorting
        wrapper.vm.sortBy('cve_id')

        // Filters should still be active
        expect(wrapper.vm.filters.severidad).toBe('critical')
        expect(wrapper.vm.filters.agente).toBe('Agent-1')
        expect(wrapper.vm.sortedVulns.length).toBe(1)
    })
})
