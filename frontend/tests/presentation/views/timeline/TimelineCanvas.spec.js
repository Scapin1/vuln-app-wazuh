import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineCanvas from '@/presentation/views/timeline/components/TimelineCanvas.vue'

const visibleSlots = [
  {
    startMs: 1,
    painted: true,
    type: 'detection',
    tickLabel: '08/03',
    cardLabel: '08/03 2026',
    total: 4,
    pending: 3,
    resolved: 1,
    details: [{ id: 1 }]
  },
  {
    startMs: 2,
    painted: false,
    type: 'none',
    tickLabel: '09/03',
    cardLabel: '09/03 2026',
    total: 0,
    pending: 0,
    resolved: 0,
    details: []
  }
]

describe('TimelineCanvas.vue', () => {
  it('renders timeline metrics and emits open-slot', async () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        allSlots: visibleSlots,
        visibleSlots,
        paintedCount: 1,
        yearLabel: '2026',
        activeZoom: { label: '30D' },
        canMoveLeft: true,
        canMoveRight: false,
        canZoomIn: true,
        canZoomOut: true
      }
    })

    expect(wrapper.text()).toContain('2026')

    await wrapper.find('.event-card').trigger('click')
    expect(wrapper.emitted('open-slot')).toBeTruthy()
  })
})
