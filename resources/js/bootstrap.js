import axios from 'axios';
import { useRouter } from 'vue-router';
window.axios = axios;

window.axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';

axios.defaults.baseURL ='/http://127.0.0.1:8000/api/v1/';

axios.defaults.withCredentials = true;


const api = axios.create({
  baseURL: 'http://127.0.0.1:8000/api/v1/',
  timeout: 10000
})

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token') // Get saved token
    config.headers.Accept ='application/json'
    if (token) {
      config.headers.Authorization = `Bearer ${token}` // Attach token
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)


api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Unauthorized → clear token and go to login
      localStorage.removeItem('token')
      useRouter().push('/login');
    }
    return Promise.reject(error)
  }
)

export default api;
