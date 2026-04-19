import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/v1',
})

// API key sources, in priority order:
//   1. localStorage.setItem('wairz.apiKey', '<key>') — runtime override
//   2. VITE_API_KEY — build-time default (CI / packaged deploy)
// Reads once at module load; reload the page after changing localStorage.
export function getApiKey(): string | null {
  if (typeof window !== 'undefined') {
    const fromStorage = window.localStorage.getItem('wairz.apiKey')
    if (fromStorage) return fromStorage
  }
  const fromEnv = import.meta.env.VITE_API_KEY as string | undefined
  return fromEnv || null
}

// Append ?api_key=<key> to a URL. Used for WebSocket URLs where the
// browser can't set custom headers (Sec-WebSocket-* is kernel-controlled).
// Prefer the X-API-Key header for HTTP — query-param path leaks the key
// into uvicorn access logs.
export function appendApiKey(url: string): string {
  const key = getApiKey()
  if (!key) return url
  const sep = url.includes('?') ? '&' : '?'
  return `${url}${sep}api_key=${encodeURIComponent(key)}`
}

// Per-request interceptor so key resolution happens at the latest
// possible moment (picks up localStorage changes without a page reload,
// and guarantees no module-load race).
apiClient.interceptors.request.use((config) => {
  const key = getApiKey()
  if (key && !config.headers.has('X-API-Key')) {
    config.headers.set('X-API-Key', key)
  }
  return config
})

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
