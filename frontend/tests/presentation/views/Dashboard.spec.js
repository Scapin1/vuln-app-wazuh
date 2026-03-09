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

        wazuhService.getConnections.mockResolvedValue({ data: [] })
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

    it('filters vulnerabilities by selected agent', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedAgents = ['Agent-1']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].agent_name).toBe('Agent-1')
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

    it('filters vulnerabilities by selected severity', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedSeverities = ['CRITICAL']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].severity).toBe('critical')
    })

    it('filters vulnerabilities by selected cve', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedVulns = ['CVE-2023-1234']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].cve_id).toBe('CVE-2023-1234')
    })

    it('filters vulnerabilities by selected package', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedPackages = ['bash']
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].package_name).toBe('bash')
    })

    it('clears filters correctly', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedConnection = 1
        wrapper.vm.selectedAgents = ['Agent-1']
        wrapper.vm.selectedVulns = ['CVE-2023-1234']
        wrapper.vm.selectedPackages = ['bash']
        wrapper.vm.selectedSeverities = ['CRITICAL']
        wrapper.vm.scoreMin = 1
        wrapper.vm.scoreMax = 9

        wrapper.vm.clearFilters()
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.selectedConnection).toBe('')
        expect(wrapper.vm.selectedAgents).toEqual([])
        expect(wrapper.vm.selectedVulns).toEqual([])
        expect(wrapper.vm.selectedPackages).toEqual([])
        expect(wrapper.vm.selectedSeverities).toEqual([])
        expect(wrapper.vm.scoreMin).toBe('')
        expect(wrapper.vm.scoreMax).toBe('')
    })

    it('covers empty vulns, loads connections, isNew and severity badge branches', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: [] })
        wazuhService.getConnections.mockResolvedValueOnce({
            data: [
            { id: 1, name: 'Conn A' },
            { id: 2, name: 'Conn B' }
            ]
        })

        const wrapper = mount(Dashboard)
        await flushPromises()

        // line 607: when vulns API returns empty
        expect(wrapper.vm.vulns).toEqual([])

        // line 619: connections assigned
        expect(wrapper.vm.connections).toEqual([
            { id: 1, name: 'Conn A' },
            { id: 2, name: 'Conn B' }
        ])

        // lines 648-653
        expect(wrapper.vm.isNew(null)).toBe(false)
        expect(wrapper.vm.isNew(new Date().toISOString())).toBe(true)
        expect(
            wrapper.vm.isNew(new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString())
        ).toBe(false)

        // lines 665-669
        expect(wrapper.vm.getSeverityBadgeClass('critical')).toBe('badge-critical')
        expect(wrapper.vm.getSeverityBadgeClass('critica')).toBe('badge-critical')
        expect(wrapper.vm.getSeverityBadgeClass('high')).toBe('badge-high')
        expect(wrapper.vm.getSeverityBadgeClass('alta')).toBe('badge-high')
        expect(wrapper.vm.getSeverityBadgeClass('medium')).toBe('badge-medium')
        expect(wrapper.vm.getSeverityBadgeClass('media')).toBe('badge-medium')
        expect(wrapper.vm.getSeverityBadgeClass('low')).toBe('badge-low')
    })

    it('clears dependent filters on connection change', async () => {
        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulns })
        wazuhService.getConnections.mockResolvedValueOnce({
            data: [{ id: 1, name: 'Conn A' }]
        })

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.selectedAgents = ['Agent-1']
        wrapper.vm.selectedVulns = ['CVE-2023-1234']
        wrapper.vm.selectedPackages = ['bash']
        wrapper.vm.selectedSeverities = ['CRITICAL']
        wrapper.vm.scoreMin = 2
        wrapper.vm.scoreMax = 9

        wrapper.vm.onConnectionChange()
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.selectedAgents).toEqual([])
        expect(wrapper.vm.selectedVulns).toEqual([])
        expect(wrapper.vm.selectedPackages).toEqual([])
        expect(wrapper.vm.selectedSeverities).toEqual([])
        expect(wrapper.vm.scoreMin).toBe('')
        expect(wrapper.vm.scoreMax).toBe('')
    })

    it('filters vulnerabilities by maximum score', async () => {
        const mockVulnsWithScore = [
            {
            id: 1,
            connection_name: 'Conn A',
            severity: 'critical',
            cve_id: 'CVE-2023-1234',
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: 'Agent-1',
            package_name: 'bash',
            package_version: '5.0',
            score_base: 9.8
            },
            {
            id: 2,
            connection_name: 'Conn B',
            severity: 'low',
            cve_id: 'CVE-2022-0001',
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: 'Agent-2',
            package_name: 'curl',
            package_version: '7.0',
            score_base: 4.2
            }
        ]

        vulnService.getVulns.mockResolvedValueOnce({ data: mockVulnsWithScore })
        wazuhService.getConnections.mockResolvedValueOnce({ data: [] })

        const wrapper = mount(Dashboard)
        await flushPromises()

        wrapper.vm.scoreMax = 5
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.sortedVulns.length).toBe(1)
        expect(wrapper.vm.sortedVulns[0].id).toBe(2)
    })

    it('computes visible pages and navigates across pages correctly', async () => {
        const manyVulns = Array.from({ length: 500 }, (_, i) => ({
            id: i + 1,
            connection_name: `Conn ${i + 1}`,
            severity: i % 2 === 0 ? 'critical' : 'low',
            cve_id: `CVE-2023-${String(i + 1).padStart(4, '0')}`,
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: `Agent-${i + 1}`,
            package_name: `pkg-${i + 1}`,
            package_version: '1.0',
            score_base: (i % 10) + 1
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: manyVulns })
        wazuhService.getConnections.mockResolvedValueOnce({ data: [] })

        const wrapper = mount(Dashboard)
        await flushPromises()

        // 500 / 50 = 10 páginas
        expect(wrapper.vm.totalPages).toBe(10)

        // currentPage = 1 por defecto
        // cubre visiblePages cuando total > 7
        expect(wrapper.vm.visiblePages).toEqual([1, 2, 3, 4, 5, 6, 'right-ellipsis', 10])

        // line 539: nextPage
        wrapper.vm.nextPage()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(2)

        // line 543: prevPage
        wrapper.vm.prevPage()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(1)

        // moverse a una página intermedia para cubrir left/right ellipsis
        wrapper.vm.currentPage = 5
        await wrapper.vm.$nextTick()

        expect(wrapper.vm.visiblePages).toEqual([
            1,
            'left-ellipsis',
            3,
            4,
            5,
            6,
            7,
            'right-ellipsis',
            10
        ])

        // line 547: jumpBackward
        wrapper.vm.jumpBackward()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(1)

        // lines 550-552: jumpForward
        wrapper.vm.jumpForward()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(10)

        // nextPage no debe pasar del máximo
        wrapper.vm.nextPage()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(10)

        // prevPage vuelve una
        wrapper.vm.prevPage()
        await wrapper.vm.$nextTick()
        expect(wrapper.vm.currentPage).toBe(9)
    })

    it('shows all pages when total pages are 7 or fewer', async () => {
        const fewVulns = Array.from({ length: 120 }, (_, i) => ({
            id: i + 1,
            connection_name: `Conn ${i + 1}`,
            severity: 'low',
            cve_id: `CVE-2023-${i + 1}`,
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            agent_name: `Agent-${i + 1}`,
            package_name: `pkg-${i + 1}`,
            package_version: '1.0',
            score_base: 3
        }))

        vulnService.getVulns.mockResolvedValueOnce({ data: fewVulns })
        wazuhService.getConnections.mockResolvedValueOnce({ data: [] })

        const wrapper = mount(Dashboard)
        await flushPromises()

        expect(wrapper.vm.totalPages).toBe(3)
        expect(wrapper.vm.visiblePages).toEqual([1, 2, 3])
    })
})
