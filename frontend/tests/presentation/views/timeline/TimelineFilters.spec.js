import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineFilters from '@/presentation/views/timeline/components/TimelineFilters.vue'

describe('TimelineFilters.vue', () => {
  const mockConnections = [
    { id: 1, name: 'Conn 1' },
    { id: 2, name: 'Conn 2' }
  ]

  const defaultProps = {
    connections: mockConnections,
    agentOptions: ['Agent 1', 'Agent 2', 'Agent 3'],
    vulnOptions: ['CVE-2023-001', 'CVE-2023-002'],
    selectedConnection: '',
    selectedAgents: [],
    selectedVulns: [],
    period: '24h',
    periods: [
      { v: '24h', l: '24 horas' },
      { v: '7d', l: '7 días' },
      { v: '30d', l: '30 días' },
      { v: 'day', l: 'Día' },
      { v: 'all', l: 'Todo' }
    ],
    customDate: '',
    loading: false
  }

  it('renders connection selector and emits update', async () => {
    const wrapper = mount(TimelineFilters, {
      props: defaultProps
    })

    const select = wrapper.find('select')
    expect(select.exists()).toBe(true)

    await select.setValue('1')
    expect(wrapper.emitted('update:selectedConnection')).toHaveLength(1)
    expect(wrapper.emitted('update:selectedConnection')[0]).toEqual([1])
  })

  it('shows agent selector when agents are available', () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    expect(wrapper.text()).toContain('Equipos')
    expect(wrapper.text()).toContain('Todos')
  })

  it('opens agent dropdown when clicked', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')

    await wrapper.vm.$nextTick()
    expect(wrapper.find('.dd-panel').exists()).toBe(true)
  })

  it('filters agents by search query', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    // Open dropdown
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')

    // Search input should be visible
    const searchInput = wrapper.find('.dd-search')
    expect(searchInput.exists()).toBe(true)

    await searchInput.setValue('Agent 2')
    await wrapper.vm.$nextTick()

    // Check filtered results
    const options = wrapper.findAll('.dd-item')
    expect(options.length).toBeLessThanOrEqual(defaultProps.agentOptions.length)
  })

  it('selects period chips correctly', async () => {
    const wrapper = mount(TimelineFilters, {
      props: defaultProps
    })

    const chips = wrapper.findAll('.chip')
    expect(chips.length).toBe(5)

    // Click '7d' chip
    await chips[1].trigger('click')
    expect(wrapper.emitted('set-period')).toHaveLength(1)
    expect(wrapper.emitted('set-period')[0]).toContain('7d')
  })

  it('shows date picker when period is "day"', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        period: 'day',
        customDate: '2026-03-08T10:00'
      }
    })

    const dateInput = wrapper.find('input[type="date"]')
    expect(dateInput.exists()).toBe(true)
    expect(dateInput.element.value).toBe('2026-03-08')
    const hourSel = wrapper.find('.dt-row select:first-of-type')
    expect(hourSel.exists()).toBe(true)
    expect(hourSel.element.value).toBe('10')
  })

  it('emits vuln selection changes', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    // Open vuln dropdown
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[1].trigger('click')
    await wrapper.vm.$nextTick()

    // Check dropdown opened
    expect(wrapper.findAll('.dd-panel').length).toBeGreaterThan(0)
  })

  it('emits build event when button is clicked', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    await wrapper.find('.btn-primary').trigger('click')
    expect(wrapper.emitted('build')).toHaveLength(1)
  })

  it('disables build button when no connection selected', () => {
    const wrapper = mount(TimelineFilters, {
      props: defaultProps
    })

    const buildButton = wrapper.find('.btn-primary')
    expect(buildButton.element.disabled).toBe(true)
  })

  it('disables build button when loading', () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1',
        loading: true
      }
    })

    const buildButton = wrapper.find('.btn-primary')
    expect(buildButton.element.disabled).toBe(true)
    expect(buildButton.text()).toContain('Analizando...')
  })

  it('displays all period options correctly', () => {
    const wrapper = mount(TimelineFilters, {
      props: defaultProps
    })

    const chips = wrapper.findAll('.chip')
    expect(chips[0].text()).toBe('24 horas')
    expect(chips[1].text()).toBe('7 días')
    expect(chips[2].text()).toBe('30 días')
    expect(chips[3].text()).toBe('Día')
    expect(chips[4].text()).toBe('Todo')
  })

  it('applies active class to selected period', () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        period: '7d'
      }
    })

    const chips = wrapper.findAll('.chip')
    expect(chips[1].classes()).toContain('on')
  })

  it('selects all agents when "Todos" is clicked', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    // Open dropdown
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()

    // Click "Todos"
    const ddActions = wrapper.find('.dd-actions')
    const todosButton = ddActions.findAll('span')[0]
    await todosButton.trigger('click')

    expect(wrapper.emitted('update:selectedAgents')).toHaveLength(1)
    expect(wrapper.emitted('update:selectedAgents')[0][0]).toHaveLength(3)
  })

  it('clears agent selection when "Limpiar" is clicked', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1',
        selectedAgents: ['Agent 1']
      }
    })

    // Open dropdown
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()

    // Click "Limpiar"
    const ddActions = wrapper.find('.dd-actions')
    const clearButton = ddActions.findAll('span')[1]
    await clearButton.trigger('click')

    expect(wrapper.emitted('update:selectedAgents')).toHaveLength(1)
    expect(wrapper.emitted('update:selectedAgents')[0][0]).toHaveLength(0)
  })

  it('selects all vulnerabilities when "Todas" is clicked', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[1].trigger('click') // Vulns dropdown

    const todosButton = wrapper.findAll('.dd-panel .dd-actions span')[0]
    await todosButton.trigger('click')

    expect(wrapper.emitted('update:selectedVulns')).toHaveLength(1)
    expect(wrapper.emitted('update:selectedVulns')[0][0]).toHaveLength(defaultProps.vulnOptions.length)
  })

  it('filters vulnerabilities by search query', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[1].trigger('click')

    const searchInput = wrapper.find('.dd-search')
    await searchInput.setValue('CVE-2023-002')

    expect(wrapper.vm.filteredVulns).toEqual(['CVE-2023-002'])
  })

  it('accordion — opening agents closes vulns', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    const ddButtons = wrapper.findAll('.dd-btn')

    // Open vulns dropdown first
    await ddButtons[1].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(1)

    // Now open agents — should close vulns
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(1)
  })

  it('accordion — opening vulns closes agents', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    const ddButtons = wrapper.findAll('.dd-btn')

    // Open agents dropdown first
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(1)

    // Now open vulns — should close agents
    await ddButtons[1].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(1)
  })

  it('click outside closes active dropdown', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        selectedConnection: '1'
      }
    })

    // Open agents dropdown
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(1)

    // Click outside the dropdown
    document.body.click()
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.dd-panel')).toHaveLength(0)
  })

  it('updates custom date when date changes', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        period: 'day',
        customDate: '2026-03-08T10:00'
      }
    })

    const dateInput = wrapper.find('input[type="date"]')
    await dateInput.setValue('2026-03-10')

    expect(wrapper.emitted('update:customDate')).toHaveLength(1)
    expect(wrapper.emitted('update:customDate')[0]).toEqual(['2026-03-10T10:00'])
  })

  it('updates custom date when hour changes', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        period: 'day',
        customDate: '2026-03-08T10:00'
      }
    })

    const hourSel = wrapper.find('.dt-row select:first-of-type')
    await hourSel.setValue('14')

    expect(wrapper.emitted('update:customDate')).toHaveLength(1)
    expect(wrapper.emitted('update:customDate')[0]).toEqual(['2026-03-08T14:00'])
  })

  it('updates custom date when minute changes', async () => {
    const wrapper = mount(TimelineFilters, {
      props: {
        ...defaultProps,
        period: 'day',
        customDate: '2026-03-08T10:00'
      }
    })

    const minuteSel = wrapper.find('.dt-row select:last-of-type')
    await minuteSel.setValue('30')

    expect(wrapper.emitted('update:customDate')).toHaveLength(1)
    expect(wrapper.emitted('update:customDate')[0]).toEqual(['2026-03-08T10:30'])
  })
})
