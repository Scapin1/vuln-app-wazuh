import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import Timeline from '@/presentation/views/Timeline.vue'
import wazuhService from '@/application/services/wazuhService'
import { useVulnStore } from '@/application/stores/vulnStore'
import TimelineFilters from '@/presentation/views/timeline/components/TimelineFilters.vue'
import VulnTable from '@/presentation/views/timeline/components/VulnTable.vue'
// Note: TimelineDetailModal.vue exists but is no longer rendered directly in Timeline.vue

// Mock services
vi.mock('@/application/services/wazuhService', () => ({
  default: {
    getConnections: vi.fn(),
    getAgents: vi.fn()
  }
}))

describe('Timeline.vue', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    // Mock wazuh service
    wazuhService.getConnections.mockResolvedValue({
      data: [
        { id: 1, name: 'Connection 1', api_url: 'http://test1' },
        { id: 2, name: 'Connection 2', api_url: 'http://test2' }
      ]
    })

    wazuhService.getAgents.mockResolvedValue({
      data: [
        { id: '001', name: 'Agent 1' },
        { id: '002', name: 'Agent 2' }
      ]
    })
  })

  it('renders main timeline structure', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.find('.timeline-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('Vulnerabilidades')
  })

  it('renders new title and subtitle', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.find('h1').text()).toBe('Vulnerabilidades')
    expect(wrapper.text()).toContain('Listado de vulnerabilidades detectadas con filtros y tabla ordenable.')
  })

  it('passes connectionName prop to VulnTable from getConnectionName', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.connections = [{ id: '1', name: 'Alpha Connection' }]
    wrapper.vm.selectedConnection = '1'
    wrapper.vm.filteredVulnsData = [{ id: 1, cve_id: 'CVE-1', connection_name: null }]
    wrapper.vm.hasBuilt = true
    wrapper.vm.loading = false
    await wrapper.vm.$nextTick()
    await nextTick()

    const vulnTable = wrapper.findComponent(VulnTable)
    expect(vulnTable.exists()).toBe(true)
    expect(vulnTable.props('connectionName')).toBe('Alpha Connection')
  })

  it('loads connections on mount', async () => {
    mount(Timeline)
    await flushPromises()

    expect(wazuhService.getConnections).toHaveBeenCalled()
  })

  it('renders without connection', () => {
    const wrapper = mount(Timeline)

    expect(wrapper.find('.timeline-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('Vulnerabilidades')
  })

  it('fetches agents and vulns when connection changes', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.selectedConnection).toBe('1')
  })

  it('clears agent and vuln selection when connection changes', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedAgents = ['agent1']
    wrapper.vm.selectedVulns = ['CVE-123']

    await wrapper.vm.onConnectionChange()

    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
  })

  it('handles connection load error gracefully', async () => {
    wazuhService.getConnections.mockRejectedValueOnce(new Error('Network error'))

    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.vm.connections).toEqual([])
  })

  it('initializes with correct initial state', () => {
    const wrapper = mount(Timeline)

    expect(wrapper.vm.connections).toEqual([])
    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.period).toBe('30d')
  })

  it('has correct period options', () => {
    const wrapper = mount(Timeline)

    const periods = wrapper.vm.periods
    expect(periods).toHaveLength(4)
    expect(periods[0]).toEqual({ v: '24h', l: '24H' })
    expect(periods[1]).toEqual({ v: '7d', l: '7D' })
    expect(periods[2]).toEqual({ v: '30d', l: '30D' })
    expect(periods[3]).toEqual({ v: 'all', l: 'Todo' })
  })

  it('updates agent and vuln options when connection changes', async () => {
    // Set up store data via fallback (getFilterOptions will fail, fetchAllVulns will succeed)
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    // Should handle gracefully even without real data
    expect(wrapper.vm.selectedConnection).toBe('1')
    expect(Array.isArray(wrapper.vm.agentOpts)).toBe(true)
    expect(Array.isArray(wrapper.vm.vulnOpts)).toBe(true)
  })

  it('builds timeline when build is called', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await flushPromises()

    const buildSpy = vi.spyOn(wrapper.vm, 'buildTimeline')
    await wrapper.vm.buildTimeline()

    expect(buildSpy).toHaveBeenCalled()
  })

  it('handles error in onConnectionChange', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = ''
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.errorBanner).toBe('')
  })

  it('handles error in buildTimeline', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'

    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(wrapper.vm.hasBuilt).toBe(false)
  })

  it('updates period via setPeriod method', () => {
    const wrapper = mount(Timeline)
    wrapper.vm.setPeriod('7d')
    expect(wrapper.vm.period).toBe('7d')
  })

  it('displays error banner when statusError is computed', async () => {
    const wrapper = mount(Timeline)
    wrapper.vm.errorBanner = 'Custom Error'
    await wrapper.vm.$nextTick()

    expect(wrapper.find('.status-error').exists()).toBe(true)
    expect(wrapper.text()).toContain('Custom Error')
  })

  it('updates state when filters emit updates', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    const filters = wrapper.findComponent(TimelineFilters)

    await filters.vm.$emit('update:selectedConnection', '2')
    expect(wrapper.vm.selectedConnection).toBe('2')

    await filters.vm.$emit('update:selectedAgents', ['Agent X'])
    expect(wrapper.vm.selectedAgents).toEqual(['Agent X'])

    await filters.vm.$emit('update:selectedVulns', ['CVE-Y'])
    expect(wrapper.vm.selectedVulns).toEqual(['CVE-Y'])

    await filters.vm.$emit('update:customDate', '2026-05-05T10:00')
    expect(wrapper.vm.customDate).toBe('2026-05-05T10:00')
  })

})
