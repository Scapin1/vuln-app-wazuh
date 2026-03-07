import apiClient from '../../infrastructure/http/apiClient';

const userService = {
  getUsers: async () => {
    return apiClient.get('/users')
  },

  createUser: async (userData) => {
    return apiClient.post('/users', userData)
  }
}

export default userService