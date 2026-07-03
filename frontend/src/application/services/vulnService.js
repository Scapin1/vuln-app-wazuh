import apiClient from '../../infrastructure/http/apiClient';

export default {
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
}
