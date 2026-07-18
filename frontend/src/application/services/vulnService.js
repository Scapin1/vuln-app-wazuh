import apiClient from '../../infrastructure/http/apiClient'

export default {
  // ── Current endpoint (keep as fallback) ──
  getVulns: async (params = {}, extraConfig = {}) => {
    const queryParams = {}

    if (params.limit !== undefined && params.limit !== null) {
      queryParams.limit = params.limit
    }

    if (params.connectionId !== undefined && params.connectionId !== null) {
      queryParams.connection_id = params.connectionId
    }

    if (params.offset !== undefined && params.offset !== null) {
      queryParams.offset = params.offset
    }

    return apiClient.get('/vulns', {
      params: queryParams,
      ...extraConfig,
    })
  },

  syncVulns: async () => {
    return apiClient.post('/vulns/sync-all')
  },

  // ── New aggregation APIs ──

  /**
   * GET /api/vulns/dashboard
   * Dashboard summary: severity/status distributions + total count
   */
  getDashboardSummary: async (connectionId, period, customDate) => {
    return apiClient.get('/vulns/dashboard', {
      params: {
        connection_id: connectionId,
        period: period || '30d',
        date: customDate || undefined
      }
    })
  },

  /**
   * GET /api/vulns/timeline/gantt
   * Paginated CVE snapshot data for GanttTab
   * Response includes min_timestamp/max_timestamp for timeline header
   */
  getTimeline: async (connectionId, period, customDate, page = 1, perPage = 20, filters = {}) => {
    const params = {
      connection_id: connectionId,
      period: period || 'all',
      date: customDate || undefined,
      page,
      per_page: perPage
    }
    if (filters.agent) params.agent = filters.agent
    if (filters.severity) params.severity = filters.severity
    if (filters.search) params.search = filters.search

    return apiClient.get('/vulns/timeline/gantt', { params })
  },

  /**
   * GET /api/vulns/analytics
   * Analytics metrics: distributions + top agents + critical info
   */
  getAnalytics: async (connectionId, period, customDate) => {
    return apiClient.get('/vulns/analytics', {
      params: {
        connection_id: connectionId,
        period: period || '30d',
        date: customDate || undefined
      }
    })
  },

  /**
   * GET /api/vulns/filter-options
   * Distinct agents and CVEs for filter dropdowns
   */
  getFilterOptions: async (connectionId) => {
    return apiClient.get('/vulns/filter-options', {
      params: { connection_id: connectionId }
    })
  },

  /**
   * GET /api/vulns/events
   * Detection/resolution events for timeline slots
   */
  getTimelineEvents: async (connectionId, startMs, endMs) => {
    return apiClient.get('/vulns/events', {
      params: {
        connection_id: connectionId,
        start_ms: startMs,
        end_ms: endMs
      }
    })
  },

  /**
   * GET /api/vulns/analytics/critical-view
   * Critical CVEs from materialized view (global — todas las conexiones)
   */
  getCriticalView: async () => {
    return apiClient.get('/vulns/analytics/critical-view')
  },

  /**
   * POST /api/vulns/analytics/refresh-critical
   * Refresca la vista materializada de CVEs críticos
   */
  refreshCriticalView: async () => {
    return apiClient.post('/vulns/analytics/refresh-critical')
  }
}
