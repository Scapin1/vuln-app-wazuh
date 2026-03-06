import apiClient from '../../infrastructure/http/apiClient';

export default {
    getConfig: async () => {
        return apiClient.get('/wazuh-config');
    },
    updateConfig: async (configData) => {
        return apiClient.put('/wazuh-config', configData);
    }
}
