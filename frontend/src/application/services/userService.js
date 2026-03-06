import apiClient from '../../infrastructure/http/apiClient';

export default {
    getMe: async () => {
        return apiClient.get('/users/me');
    },
    createUser: async (userData) => {
        return apiClient.post('/users', userData);
    }
}
