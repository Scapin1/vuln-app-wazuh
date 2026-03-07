import apiClient from '../../infrastructure/http/apiClient';

const wazuhService = {
  getConnections: async () => {
    return apiClient.get('/wazuh-connections')
  },

  createConnection: async (connectionData) => {
    return apiClient.post('/wazuh-connections', connectionData)
  }
}

export default wazuhService

