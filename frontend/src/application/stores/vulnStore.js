import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import vulnService from '../services/vulnService'

const CACHE_TTL_MS = 60_000 // 1 minuto
const PAGE_SIZE = 10000

// ── Module-level helpers ──

async function fetchAllVulns(connectionId, signal) {
  let allData = []
  let offset = 0

  while (true) {
    if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')

    const res = await vulnService.getVulns(
      { connectionId, limit: PAGE_SIZE, offset },
      { signal }
    )
    const data = Array.isArray(res.data) ? res.data : []
    allData = allData.concat(data)

    if (data.length < PAGE_SIZE) break
    offset += PAGE_SIZE
  }

  return allData
}

function computeStatusDistribution(vulns) {
  const counts = { Detected: 0, Resolved: 0, 'Re-emerged': 0 }
  vulns.forEach(v => {
    if (v.status && counts[v.status] !== undefined) counts[v.status]++
  })
  return counts
}

function computeTopAgents(vulns, limit = 5) {
  const agentMap = {}
  vulns.forEach(v => {
    const agent = v.agent_name || 'unknown'
    agentMap[agent] = (agentMap[agent] || 0) + 1
  })
  return Object.entries(agentMap)
    .map(([agent, count]) => ({ agent, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

function computeCriticalInfo(vulns) {
  const criticalVulns = vulns.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL')
  const count = criticalVulns.length
  const cveCounts = {}
  criticalVulns.forEach(v => {
    if (v.cve_id) cveCounts[v.cve_id] = (cveCounts[v.cve_id] || 0) + 1
  })
  const sorted = Object.entries(cveCounts).sort((a, b) => b[1] - a[1])
  return { count, topCve: sorted.length > 0 ? sorted[0][0] : null }
}

function computeFilterOptions(vulns) {
  const agents = new Set()
  const cves = new Set()
  vulns.forEach(v => {
    if (v.agent_name) agents.add(v.agent_name)
    if (v.cve_id) cves.add(v.cve_id)
  })
  return {
    agents: Array.from(agents).sort((a, b) => a.localeCompare(b)),
    cves: Array.from(cves).sort((a, b) => a.localeCompare(b))
  }
}

function processAgentTimestamps(cve) {
  const timestampMap = new Map()
  cve.agents.forEach(agent => {
    const addTimestamp = (ts) => {
      if (!ts) return
      if (!timestampMap.has(ts)) timestampMap.set(ts, new Set())
      timestampMap.get(ts).add(agent.agent_name)
    }
    addTimestamp(agent.first_seen)
    addTimestamp(agent.last_seen)
    agent.history.forEach(h => addTimestamp(h.timestamp))
  })
  return timestampMap
}

function buildSortedTimestamps(timestampMap, cve) {
  const sortedTimestamps = Array.from(timestampMap.keys()).sort(
    (a, b) => new Date(a).getTime() - new Date(b).getTime()
  )

  return sortedTimestamps.map(ts => ({
    syncTimestamp: ts,
    agents: Array.from(timestampMap.get(ts) || []),
    agentCount: (timestampMap.get(ts) || new Set()).size,
    cve_id: cve.cve_id
  }))
}

export const useVulnStore = defineStore('vulns', () => {
  // ── Cache (por connectionId:tipo) ──
  const cache = ref(new Map())

  // ── Estado global ──
  const loading = ref(false)
  const error = ref(null)
  const activeConnectionId = ref(null)

  // ── Cache helpers ──
  function cacheKey(type) {
    return `${activeConnectionId.value}:${type}`
  }

  function getCached(type, ttlMs = CACHE_TTL_MS) {
    const key = cacheKey(type)
    const entry = cache.value.get(key)
    if (!entry) return null
    if (Date.now() - entry.timestamp > ttlMs) {
      cache.value.delete(key)
      return null
    }
    return entry.data
  }

  function setCache(type, data) {
    const key = cacheKey(type)
    cache.value.set(key, { data, timestamp: Date.now() })
  }

  function invalidateCache() {
    cache.value.clear()
  }

  // ── Helpers de filtrado ──
  function filterByPeriod(vulns, period, customDate) {
    if (!period || period === 'all') return vulns

    const now = new Date()
    let startMs

    switch (period) {
      case '24h': startMs = now.getTime() - 24 * 60 * 60 * 1000; break
      case '7d':  startMs = now.getTime() - 7 * 24 * 60 * 60 * 1000; break
      case '30d': startMs = now.getTime() - 30 * 24 * 60 * 60 * 1000; break
      case 'day':
        if (customDate) {
          const d = new Date(`${customDate}T00:00:00`)
          startMs = d.getTime()
          const endMs = startMs + 24 * 60 * 60 * 1000
          return vulns.filter(v => {
            const ts = new Date(v.first_seen || v.last_seen).getTime()
            return ts >= startMs && ts <= endMs
          })
        }
        return vulns
      default: return vulns
    }

    return vulns.filter(v => {
      const ts = new Date(v.last_seen || v.first_seen).getTime()
      return ts >= startMs
    })
  }

  function computeSeverityDistribution(vulns) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    vulns.forEach(v => {
      const sev = (v.severity || 'LOW').toUpperCase()
      if (counts[sev] !== undefined) counts[sev]++
    })
    return counts
  }

  // ── Dashboard Summary ──
  async function fetchDashboardSummary(connectionId, period, customDate) {
    activeConnectionId.value = connectionId
    const cached = getCached('dashboard')
    if (cached) return cached

    loading.value = true
    error.value = null

    try {
      // Try new API endpoint
      const res = await vulnService.getDashboardSummary(connectionId, period, customDate)
      const data = res.data
      setCache('dashboard', data)
      return data
    } catch (apiErr) {
      console.warn('[vulnStore] API fallback:', apiErr)
      // API not available yet → fallback client-side
      const allVulns = await fetchAllVulns(connectionId)
      const filtered = filterByPeriod(allVulns, period, customDate)

      const data = {
        severity_distribution: computeSeverityDistribution(filtered),
        status_distribution: computeStatusDistribution(filtered),
        total: filtered.length
      }
      setCache('dashboard', data)
      return data
    } finally {
      loading.value = false
    }
  }

  // ── Timeline / Gantt Data ──
  async function fetchTimeline(connectionId, period, customDate, page = 1, perPage = 20, filters = {}) {
    activeConnectionId.value = connectionId
    const cacheType = `timeline:${period}:${customDate || ''}:${page}:${perPage}`
    const cached = getCached(cacheType)
    if (cached) return cached

    loading.value = true
    error.value = null

    try {
      // Try new API endpoint
      const res = await vulnService.getTimeline(connectionId, period, customDate, page, perPage, filters)
      const data = res.data
      // Cache only first page (pagination is cheap, don't cache every page)
      if (page === 1) setCache(cacheType, data)
      return data
    } catch (apiErr) {
      console.warn('[vulnStore] API fallback:', apiErr)
      // Fallback: fetch all vulns, group by CVE, build snapshots
      const allVulns = await fetchAllVulns(connectionId)
      const filtered = filterByPeriod(allVulns, period, customDate)
      const cves = buildCveSnapshots(filtered)

      // Compute global min/max across all CVEs for timeline header
      let minTimestamp = null
      let maxTimestamp = null
      cves.forEach(cve => {
        if (cve.firstSync && (!minTimestamp || cve.firstSync < minTimestamp)) minTimestamp = cve.firstSync
        if (cve.lastSync && (!maxTimestamp || cve.lastSync > maxTimestamp)) maxTimestamp = cve.lastSync
      })

      const totalPages = Math.max(1, Math.ceil(cves.length / perPage))
      const start = (page - 1) * perPage
      const paginated = cves.slice(start, start + perPage)

      const data = {
        cves: paginated,
        total_cves: cves.length,
        total_pages: totalPages,
        current_page: page,
        per_page: perPage,
        min_timestamp: minTimestamp,
        max_timestamp: maxTimestamp
      }

      // Only cache first page (full dataset is too large)
      if (page === 1) setCache(cacheType, data)
      return data
    } finally {
      loading.value = false
    }
  }

  // ── Analytics ──
  async function fetchAnalytics(connectionId, period, customDate) {
    activeConnectionId.value = connectionId
    const cached = getCached('analytics')
    if (cached) return cached

    loading.value = true
    error.value = null

    try {
      const res = await vulnService.getAnalytics(connectionId, period, customDate)
      const data = res.data
      setCache('analytics', data)
      return data
    } catch (apiErr) {
      console.warn('[vulnStore] API fallback:', apiErr)
      // Fallback client-side
      const allVulns = await fetchAllVulns(connectionId)
      const filtered = filterByPeriod(allVulns, period, customDate)

      // Map API status to display status
      const displayStatus = (status) => {
        const map = { Detected: 'Activo', Resolved: 'Resuelto', 'Re-emerged': 'Reabierto' }
        return map[status] || status || 'Activo'
      }

      const statusDist = {}
      filtered.forEach(v => {
        const s = displayStatus(v.status)
        statusDist[s] = (statusDist[s] || 0) + 1
      })

      const data = {
        severity_distribution: computeSeverityDistribution(filtered),
        status_distribution: statusDist,
        top_agents: computeTopAgents(filtered),
        critical_count: computeCriticalInfo(filtered).count,
        top_critical_cve: computeCriticalInfo(filtered).topCve
      }
      setCache('analytics', data)
      return data
    } finally {
      loading.value = false
    }
  }

  // ── Filter Options ──
  async function fetchFilterOptions(connectionId) {
    activeConnectionId.value = connectionId
    const cached = getCached('filters', 120_000) // 2 min TTL
    if (cached) return cached

    loading.value = true
    error.value = null

    try {
      const res = await vulnService.getFilterOptions(connectionId)
      const data = res.data
      setCache('filters', data)
      return data
    } catch (apiErr) {
      console.warn('[vulnStore] API fallback:', apiErr)
      // Fallback client-side
      const allVulns = await fetchAllVulns(connectionId)
      const options = computeFilterOptions(allVulns)
      setCache('filters', options)
      return options
    } finally {
      loading.value = false
    }
  }

  // ── Timeline Events ──
  async function fetchTimelineEvents(connectionId, startMs, endMs) {
    activeConnectionId.value = connectionId
    const cacheType = `events:${startMs}:${endMs}`
    const cached = getCached(cacheType)
    if (cached) return cached

    loading.value = true
    error.value = null

    try {
      const res = await vulnService.getTimelineEvents(connectionId, startMs, endMs)
      const data = res.data
      setCache(cacheType, data)
      return data
    } catch (apiErr) {
      console.warn('[vulnStore] API fallback:', apiErr)
      // Fallback: compute from vuln data with history
      const allVulns = await fetchAllVulns(connectionId)
      const events = []
      allVulns.forEach(vuln => {
        const firstSeenMs = new Date(vuln.first_seen).getTime()
        if (firstSeenMs >= startMs && firstSeenMs <= endMs) {
          events.push({ ms: firstSeenMs, kind: 'detection', cve_id: vuln.cve_id })
        }
        ;(vuln.historySorted || vuln.history || []).forEach(h => {
          const hMs = new Date(h.timestamp).getTime()
          if (hMs >= startMs && hMs <= endMs && h.action === 'RESOLVED') {
            events.push({ ms: hMs, kind: 'resolution', cve_id: vuln.cve_id })
          }
        })
      })
      const data = { detections: events.filter(e => e.kind === 'detection'), resolutions: events.filter(e => e.kind === 'resolution') }
      setCache(cacheType, data)
      return data
    } finally {
      loading.value = false
    }
  }

  // ── CVE snapshot builder (fallback, moved from GanttTab) ──
  function buildCveSnapshots(vulns) {
    const cveMap = new Map()

    vulns.forEach(v => {
      if (!cveMap.has(v.cve_id)) {
        cveMap.set(v.cve_id, {
          cve_id: v.cve_id,
          severity: v.severity || 'MEDIUM',
          description: v.description || '',
          agents: [],
          snapshots: [],
          isResolved: false
        })
      }
      const cve = cveMap.get(v.cve_id)
      cve.agents.push({
        agent_name: v.agent_name || 'unknown',
        agent_id: v.agent_id || '',
        first_seen: v.first_seen,
        last_seen: v.last_seen,
        history: v.historySorted || v.history || []
      })
    })

    cveMap.forEach((cve) => {
      const timestampMap = processAgentTimestamps(cve)
      cve.snapshots = buildSortedTimestamps(timestampMap, cve)

      cve.isResolved = cve.agents.length > 0 && cve.agents.every(agent => {
        const lastEvent = agent.history[agent.history.length - 1]
        return lastEvent?.action === 'RESOLVED'
      })

      cve.firstSync = cve.snapshots[0]?.syncTimestamp || null
      cve.lastSync = cve.snapshots[cve.snapshots.length - 1]?.syncTimestamp || null
    })

    return Array.from(cveMap.values())
  }

  // ── Dashboard data (raw vulns for GanttTab/VulnTable) ──
  const dashboardVulns = ref([])

  async function fetchDashboard(connectionId, period, customDate) {
    activeConnectionId.value = connectionId
    const cacheType = `dashboard-data:${period}:${customDate || ''}`
    const cached = getCached(cacheType)
    if (cached) {
      dashboardVulns.value = cached.vulns
      return cached
    }

    loading.value = true
    error.value = null

    try {
      // Try new API endpoints
      const [summaryRes, timelineRes] = await Promise.allSettled([
        vulnService.getDashboardSummary(connectionId, period, customDate),
        vulnService.getTimeline(connectionId, period, customDate, 1, 200, {})
      ])

      const summary = summaryRes.status === 'fulfilled'
        ? summaryRes.value.data
        : null

      const timeline = timelineRes.status === 'fulfilled'
        ? timelineRes.value.data
        : null

      // If both APIs worked, use them
      if (summary && timeline) {
        const result = { summary, vulns: timeline.cves }
        dashboardVulns.value = timeline.cves
        setCache(cacheType, result)
        return result
      }

      // Fallback: fetch all vulns via existing endpoint
      const allVulns = await fetchAllVulns(connectionId)
      const filtered = filterByPeriod(allVulns, period, customDate)

      const result = {
        summary: {
          severity_distribution: computeSeverityDistribution(filtered),
          status_distribution: computeStatusDistribution(filtered),
          total: filtered.length
        },
        vulns: filtered
      }
      dashboardVulns.value = filtered
      setCache(cacheType, result)
      return result
    } catch (err) {
      console.warn('[vulnStore] API fallback:', err)
      error.value = err.message || 'Error al cargar datos del dashboard'
      throw err
    } finally {
      loading.value = false
    }
  }

  // ── Clear data when connection changes ──
  function clearConnectionData() {
    dashboardVulns.value = []
  }

  return {
    // State
    loading,
    error,
    activeConnectionId,
    dashboardVulns,
    // Actions
    fetchAllVulns,
    fetchDashboardSummary,
    fetchDashboard,
    fetchTimeline,
    fetchAnalytics,
    fetchFilterOptions,
    fetchTimelineEvents,
    invalidateCache,
    clearConnectionData,
    buildCveSnapshots
  }
})
