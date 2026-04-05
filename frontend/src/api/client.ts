import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/v1',
})

// If VITE_API_KEY is set, attach it to every request.
const apiKey = import.meta.env.VITE_API_KEY as string | undefined
if (apiKey) {
  apiClient.defaults.headers.common['X-API-Key'] = apiKey
}

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ?? error.message ?? 'An error occurred'
    console.error('[API Error]', message)
    return Promise.reject(error)
  },
)

export default apiClient
