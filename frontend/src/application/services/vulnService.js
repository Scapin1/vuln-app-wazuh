import apiClient from '../../infrastructure/http/apiClient';

export default {
    getVulns: async (params = {}) => {
        return apiClient.get('/vulns', {
        params: {
            limit: params.limit ?? 100,
            connection_id: params.connectionId ?? undefined,
        },
        })
    },

  syncVulns: async () => {
    return apiClient.post('/vulns/sync-all')
  },
}
