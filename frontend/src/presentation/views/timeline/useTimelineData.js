import { computed, ref } from 'vue'
import vulnService from '../../../application/services/vulnService'
import { DAY_MS, HOUR_MS, alignHour, fmtDDMM, fmtHour, fmtYear } from './timelineFormatters'

const LIMIT = 2000

const startOfLocalDay = ms => {
  const date = new Date(ms)
  date.setHours(0, 0, 0, 0)
  return date.getTime()
}

const initialZoomForPeriod = period => {
  if (period === '7d') return 2
  if (period === '24h') return 4
  if (period === 'day') return 5
  return 0
}

export default function useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  period,
  customDate,
  activeZoom,
  getConnectionName
}) {
  const loading = ref(false)
  const hasBuilt = ref(false)
  const filteredVulnsData = ref([])
  const changeEvents = ref([])
  const latestSnap = ref({ total: 0, pending: 0, resolved: 0 })
  const rangeStartMs = ref(0)
  const rangeEndMs = ref(0)
  const errorMessage = ref('')
  const warningMessage = ref('')
  const snapshotCache = ref(new Map())

  const computeRange = vulns => {
    const now = new Date()
    let start = new Date(0)
    let end = now

    if (period.value === '24h') start = new Date(now.getTime() - DAY_MS)
    if (period.value === '7d') start = new Date(now.getTime() - 7 * DAY_MS)
    if (period.value === '30d') start = new Date(now.getTime() - 30 * DAY_MS)

    if (period.value === 'day') {
      start = new Date(`${customDate.value}T00:00:00`)
      end = new Date(`${customDate.value}T23:59:59`)
    }

    if (period.value === 'all' && vulns.length > 0) {
      const earliest = vulns
        .map(vuln => new Date(vuln.first_seen).getTime())
        .filter(ms => !Number.isNaN(ms))
        .sort((a, b) => a - b)[0]
      if (earliest) {
        start = new Date(earliest)
      }
    }

    return { start, end }
  }

  const summarizeChanges = (startMs, endMs) => {
    let hasDetection = false
    let hasResolution = false

    for (const event of changeEvents.value) {
      if (event.ms < startMs) continue
      if (event.ms > endMs) break
      if (event.kind === 'detection') hasDetection = true
      if (event.kind === 'resolution') hasResolution = true
      if (hasDetection && hasResolution) break
    }

    return { hasDetection, hasResolution }
  }

  const snapshotAt = ms => {
    if (snapshotCache.value.has(ms)) {
      return snapshotCache.value.get(ms)
    }

    let total = 0
    let pending = 0
    let resolved = 0
    const details = []

    filteredVulnsData.value.forEach(vuln => {
      const firstSeenMs = new Date(vuln.first_seen).getTime()
      if (Number.isNaN(firstSeenMs) || firstSeenMs > ms) return

      let state = 'ACTIVE'
      let resolvedAt = null

      for (const historyItem of vuln.historySorted) {
        const historyMs = new Date(historyItem.timestamp).getTime()
        if (Number.isNaN(historyMs) || historyMs > ms) break
        if (historyItem.action === 'RESOLVED') {
          state = 'RESOLVED'
          resolvedAt = historyItem.timestamp
        } else {
          state = 'ACTIVE'
          resolvedAt = null
        }
      }

      total += 1
      if (state === 'ACTIVE') pending += 1
      else resolved += 1

      details.push({
        ...vuln,
        status: state,
        resolved_at: resolvedAt,
        connection_name: getConnectionName()
      })
    })

    const snapshot = { total, pending, resolved, details }
    snapshotCache.value.set(ms, snapshot)
    return snapshot
  }

  const getTimelineEventInSlot = (vuln, startMs, endMs) => {
    const candidates = []

    const firstSeenMs = new Date(vuln.first_seen).getTime()
    if (!Number.isNaN(firstSeenMs) && firstSeenMs >= startMs && firstSeenMs <= endMs) {
      candidates.push({
        at: vuln.first_seen,
        label: 'DETECTED_APP',
        source: 'first_seen'
      })
    }

    for (const historyItem of vuln.historySorted) {
      const historyMs = new Date(historyItem.timestamp).getTime()
      if (Number.isNaN(historyMs) || historyMs < startMs || historyMs > endMs) continue

      if (['DETECTED', 'REOPENED', 'RESOLVED'].includes(historyItem.action)) {
        candidates.push({
          at: historyItem.timestamp,
          label: historyItem.action,
          source: 'history'
        })
      }
    }

    if (!candidates.length) return null

    candidates.sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime())
    return candidates[0]
  }

  const allSlots = computed(() => {
    if (!hasBuilt.value || !rangeStartMs.value || !rangeEndMs.value) return []

    const slots = []
    const slotMs = activeZoom.value.slotHours * HOUR_MS
    const isDayGranularity = activeZoom.value.slotHours >= 24
    const baseStartMs = isDayGranularity ? startOfLocalDay(rangeStartMs.value) : rangeStartMs.value
    const totalSlotCount = Math.max(1, Math.ceil((rangeEndMs.value - baseStartMs + 1) / slotMs))

    for (let index = 0; index < totalSlotCount; index++) {
      const startMs = baseStartMs + index * slotMs
      const endMs = Math.min(rangeEndMs.value, startMs + slotMs - 1)
      const summary = summarizeChanges(startMs, endMs)
      const painted = summary.hasDetection || summary.hasResolution
      const type = summary.hasDetection && summary.hasResolution
        ? 'mixed'
        : summary.hasDetection
          ? 'detection'
          : summary.hasResolution
            ? 'resolution'
            : 'none'

      const snapshot = painted ? snapshotAt(endMs) : null
      const details = snapshot?.details?.map(vuln => {
        const timelineEvent = getTimelineEventInSlot(vuln, startMs, endMs)
        return {
          ...vuln,
          timeline_event_at: timelineEvent?.at ?? null,
          timeline_event_label: timelineEvent?.label ?? null,
          timeline_event_source: timelineEvent?.source ?? null
        }
      }) ?? []

      slots.push({
        startMs,
        endMs,
        painted,
        type,
        total: snapshot?.total ?? 0,
        pending: snapshot?.pending ?? 0,
        resolved: snapshot?.resolved ?? 0,
        details,
        tickLabel: activeZoom.value.slotHours >= 24 ? fmtDDMM(startMs) : fmtHour(startMs),
        cardLabel: activeZoom.value.slotHours >= 24
          ? `${fmtDDMM(startMs)} ${fmtYear(startMs)}`
          : `${fmtDDMM(startMs)} ${fmtHour(startMs)}`
      })
    }

    return slots
  })

  const paintedCount = computed(() => allSlots.value.filter(slot => slot.painted).length)

  const fetchConnectionVulns = async () => {
    const response = await vulnService.getVulns({
      connectionId: selectedConnection.value,
      limit: LIMIT
    })

    const data = Array.isArray(response.data) ? response.data : []

    if (data.length >= LIMIT) {
      warningMessage.value = `Se alcanzaron ${LIMIT} registros. El analisis puede estar truncado.`
    }

    return data
  }

  const build = async () => {
    if (!selectedConnection.value) return { initialZoom: 0 }

    loading.value = true
    hasBuilt.value = false
    errorMessage.value = ''
    warningMessage.value = ''
    changeEvents.value = []
    filteredVulnsData.value = []
    snapshotCache.value.clear()

    try {
      const data = await fetchConnectionVulns()
      const vulns = data.filter(vuln => {
        const byAgent = selectedAgents.value.length === 0 || selectedAgents.value.includes(vuln.agent_name)
        const byVuln = selectedVulns.value.length === 0 || selectedVulns.value.includes(vuln.cve_id)
        return byAgent && byVuln
      })

      filteredVulnsData.value = vulns.map(vuln => ({
        ...vuln,
        historySorted: [...(vuln.history || [])].sort(
          (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        )
      }))

      const { start, end } = computeRange(filteredVulnsData.value)
      rangeStartMs.value = alignHour(start.getTime())
      rangeEndMs.value = end.getTime()

      const events = []
      filteredVulnsData.value.forEach(vuln => {
        const firstSeenMs = new Date(vuln.first_seen).getTime()
        if (firstSeenMs >= rangeStartMs.value && firstSeenMs <= rangeEndMs.value) {
          events.push({ ms: firstSeenMs, kind: 'detection' })
        }

        vuln.historySorted.forEach(historyItem => {
          const historyMs = new Date(historyItem.timestamp).getTime()
          if (historyMs < rangeStartMs.value || historyMs > rangeEndMs.value) return
          if (historyItem.action === 'RESOLVED') {
            events.push({ ms: historyMs, kind: 'resolution' })
          }
        })
      })

      changeEvents.value = events.sort((a, b) => a.ms - b.ms)
      latestSnap.value = snapshotAt(rangeEndMs.value)
      hasBuilt.value = true

      return { initialZoom: initialZoomForPeriod(period.value) }
    } catch (error) {
      errorMessage.value = 'No se pudo generar la linea de tiempo. Intenta nuevamente.'
      throw error
    } finally {
      loading.value = false
    }
  }

  return {
    loading,
    hasBuilt,
    allSlots,
    paintedCount,
    latestSnap,
    errorMessage,
    warningMessage,
    build,
    fetchConnectionVulns
  }
}
