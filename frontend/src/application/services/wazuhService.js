import apiClient from '../../infrastructure/http/apiClient';

const wazuhService = {
  getConnections: async () => {
    return apiClient.get('/wazuh-connections')
  },

  createConnection: async (connectionData) => {
    return apiClient.post('/wazuh-connections', connectionData)
  },

  editConnection: async (connId, connectionData) => {
    return apiClient.put(`/wazuh-connections/${connId}`, connectionData)
  }
}

export default wazuhService

