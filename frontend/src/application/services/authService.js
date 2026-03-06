import apiClient from '../../infrastructure/http/apiClient';

export default {
    login: async (credentials) => {
        return apiClient.post('/auth/login', credentials, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
    },
    changePassword: async (passwords) => {
        return apiClient.post('/auth/change-password', passwords);
    }
}
