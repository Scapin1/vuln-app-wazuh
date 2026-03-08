import { describe, it, expect } from 'vitest'
import { ref } from 'vue'
import useTimelineNavigation from '@/presentation/views/timeline/useTimelineNavigation'

describe('useTimelineNavigation', () => {
  it('calculates visibility and movement constraints', () => {
    const slotsLength = ref(120)
    const nav = useTimelineNavigation(() => slotsLength.value)

    expect(nav.visibleCount.value).toBe(30)
    expect(nav.canMoveLeft.value).toBe(false)

    nav.jumpToEnd()
    expect(nav.canMoveRight.value).toBe(false)
    expect(nav.canMoveLeft.value).toBe(true)
  })

  it('updates zoom level within bounds', () => {
    const nav = useTimelineNavigation(() => 50)

    const start = nav.zoomLevelIndex.value
    nav.zoomIn()
    expect(nav.zoomLevelIndex.value).toBe(start + 1)

    nav.setZoomLevel(999)
    expect(nav.canZoomIn.value).toBe(false)

    nav.setZoomLevel(-20)
    expect(nav.zoomLevelIndex.value).toBe(0)
  })
})
