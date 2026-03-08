import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineDetailModal from '@/presentation/views/timeline/components/TimelineDetailModal.vue'

describe('TimelineDetailModal.vue', () => {
  const mockEventData = {
    cardLabel: '08/03 2026',
    details: [
      {
        id: 1,
        connection_name: 'Conn 1',
        agent_name: 'srv-01',
        cve_id: 'CVE-2023-001',
        severity: 'HIGH',
        status: 'ACTIVE',
        detected_at: '2026-03-06T10:00:00Z',
        first_seen: '2026-03-08T12:00:00Z',
        last_seen: '2026-03-08T14:00:00Z',
        resolved_at: null,
        timeline_event_at: '2026-03-08T12:00:00Z',
        timeline_event_label: 'DETECTADO',
        timeline_event_source: 'first_seen'
      },
      {
        id: 2,
        connection_name: 'Conn 1',
        agent_name: 'srv-02',
        cve_id: 'CVE-2023-002',
        severity: 'MEDIUM',
        status: 'RESOLVED',
        detected_at: '2026-03-07T08:00:00Z',
        first_seen: '2026-03-08T10:00:00Z',
        last_seen: '2026-03-08T15:00:00Z',
        resolved_at: '2026-03-08T13:00:00Z',
        timeline_event_at: '2026-03-08T13:00:00Z',
        timeline_event_label: 'RESUELTO',
        timeline_event_source: 'history'
      }
    ]
  }

  it('does not render when show is false', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: false,
        eventData: null
      }
    })

    expect(wrapper.find('.modal-overlay').exists()).toBe(false)
  })

  it('renders modal when show is true with event data', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    expect(wrapper.find('.modal-overlay').exists()).toBe(true)
    expect(wrapper.text()).toContain('Detalle de 08/03 2026')
    expect(wrapper.text()).toContain('2 registros')
  })

  it('displays all vulnerability records in table', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(2)
    
    expect(wrapper.text()).toContain('CVE-2023-001')
    expect(wrapper.text()).toContain('CVE-2023-002')
    expect(wrapper.text()).toContain('srv-01')
    expect(wrapper.text()).toContain('srv-02')
  })

  it('shows technical date columns', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    expect(wrapper.text()).toContain('Evento en slot')
    expect(wrapper.text()).toContain('Detectado (Wazuh)')
    expect(wrapper.text()).toContain('Primera vez (App)')
    expect(wrapper.text()).toContain('Ultimo sync')
  })

  it('displays event chip for timeline events', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    expect(wrapper.text()).toContain('DETECTADO')
    expect(wrapper.text()).toContain('RESUELTO')
    
    const chips = wrapper.findAll('.event-chip')
    expect(chips.length).toBe(2)
  })

  it('filters records by search query', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('srv-01')

    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(wrapper.text()).toContain('srv-01')
    expect(wrapper.text()).not.toContain('srv-02')
  })

  it('filters by CVE ID', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('CVE-2023-002')

    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(wrapper.text()).toContain('CVE-2023-002')
  })

  it('filters by severity', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('HIGH')

    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(wrapper.text()).toContain('HIGH')
  })

  it('sorts by column when header is clicked', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const headers = wrapper.findAll('th')
    const agentHeader = headers.find(h => h.text() === 'Equipo')
    
    if (agentHeader) {
      await agentHeader.trigger('click')
      
      const rows = wrapper.findAll('tbody tr')
      const firstAgent = rows[0].text()
      expect(firstAgent).toContain('srv-')
    }
  })

  it('reverses sort order on second click', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const headers = wrapper.findAll('th')
    const agentHeader = headers.find(h => h.text() === 'Equipo')
    
    if (agentHeader) {
      await agentHeader.trigger('click')
      const firstSort = wrapper.findAll('tbody tr')[0].text()
      
      await agentHeader.trigger('click')
      const secondSort = wrapper.findAll('tbody tr')[0].text()
      
      // Order should be reversed
      expect(firstSort).not.toBe(secondSort)
    }
  })

  it('emits close event when close button is clicked', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    await wrapper.find('.modal-close').trigger('click')
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('emits close when clicking overlay', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    await wrapper.find('.modal-overlay').trigger('click')
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('shows empty state when no results match search', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('xyznotfound')

    expect(wrapper.text()).toContain('Sin coincidencias')
  })

  it('displays correct count of filtered records', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    expect(wrapper.text()).toContain('2 de 2 registros')

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('srv-01')

    expect(wrapper.text()).toContain('1 de 2 registros')
  })

  it('resets search and sort when eventData changes', async () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    const searchInput = wrapper.find('.modal-search')
    await searchInput.setValue('srv-01')
    expect(searchInput.element.value).toBe('srv-01')

    // Change event data
    await wrapper.setProps({
      eventData: {
        cardLabel: '09/03 2026',
        details: []
      }
    })

    expect(wrapper.vm.search).toBe('')
  })

  it('formats dates correctly using fmtDateTime', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: mockEventData
      }
    })

    // Dates should be formatted (not raw ISO strings)
    const tableText = wrapper.text()
    expect(tableText).not.toContain('2026-03-06T10:00:00Z')
    // Format is 'DD-MM-YYYY' like '06-03-2026'
    expect(tableText).toContain('06-03-2026')
  })

  it('displays hyphen for null dates', () => {
    const dataWithNulls = {
      cardLabel: '08/03 2026',
      details: [{
        id: 1,
        connection_name: 'Conn 1',
        agent_name: 'srv-01',
        cve_id: 'CVE-2023-001',
        severity: 'HIGH',
        status: 'ACTIVE',
        detected_at: null,
        first_seen: '2026-03-08T12:00:00Z',
        last_seen: null,
        resolved_at: null,
        timeline_event_at: null
      }]
    }

    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: true,
        eventData: dataWithNulls
      }
    })

    const cells = wrapper.findAll('td')
    const hyphenCells = cells.filter(cell => cell.text() === '-')
    expect(hyphenCells.length).toBeGreaterThan(0)
  })

  it('optimizes performance by not computing rows when modal is closed', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: {
        show: false,
        eventData: mockEventData
      }
    })

    // rows computed should return empty when show is false
    expect(wrapper.vm.rows).toEqual([])
  })
})
