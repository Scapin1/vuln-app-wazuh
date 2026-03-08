import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '../../../presentation/views/Dashboard.vue'
import vulnService from '../../../application/services/vulnService'

vi.mock('../../../application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
        syncVulns: vi.fn()
    }
}))

describe('Dashboard.vue', () => {
    const mockVulns = [
        {
            id: 1,
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
    })

    it('shows error state when getVulns fails', async () => {
        vulnService.getVulns.mockRejectedValueOnce(new Error('Network error'))
        const wrapper = mount(Dashboard)

        await flushPromises()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.error).toBe('Error al cargar los datos de vulnerabilidades.')
        expect(wrapper.text()).toContain('Error al cargar los datos de vulnerabilidades.')
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

        wrapper.vm.filters.estado = 'NUEVO'
        expect(wrapper.vm.filters.estado).toBe('NUEVO')

        wrapper.vm.clearFilters()
        expect(wrapper.vm.filters.estado).toBe('')
    })
})
