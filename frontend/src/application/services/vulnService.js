import apiClient from '../../infrastructure/http/apiClient';

export default {
    getVulns: async () => {
        return apiClient.get('/vulns');
    },
    syncVulns: async () => {
        return apiClient.post('/vulns/sync');
    }
}
