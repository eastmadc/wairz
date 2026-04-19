import axios, { AxiosError } from 'axios'
import { toast } from 'sonner'

const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 30_000,
})

// API key sources, in priority order:
//   1. localStorage.setItem('wairz.apiKey', '<key>') — runtime override
//   2. VITE_API_KEY — build-time default (CI / packaged deploy)
// Re-read on every request via the interceptor below so localStorage
// rotation picks up without a page reload.
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

// ─── Response error handling with toast dedupe ────────────────────────
//
// Show at most one toast per category every 10 seconds.  A 100-item
// bulk operation that fails every request would otherwise stack 100
// identical "Authentication failed" toasts — cosmetically bad and
// drowns out any useful signal from the first one.
//
// Keys: 'network' | 'auth' | 'forbidden' | 'server'.
const TOAST_DEDUPE_WINDOW_MS = 10_000
const lastToastAt: Record<string, number> = {}

function toastOnce(
  key: 'network' | 'auth' | 'forbidden' | 'server',
  title: string,
  description: string,
): void {
  const now = Date.now()
  const last = lastToastAt[key] ?? 0
  if (now - last < TOAST_DEDUPE_WINDOW_MS) return
  lastToastAt[key] = now
  toast.error(title, { description })
}

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    // Axios attaches `response` only when the server answered.  A
    // missing `response` means network failure, CORS block, timeout,
    // DNS error, or backend down.
    if (!error.response) {
      const isTimeout = error.code === 'ECONNABORTED'
      toastOnce(
        'network',
        isTimeout ? 'Request timed out' : 'Network error',
        isTimeout
          ? 'The backend did not respond within 30s'
          : 'Could not reach the backend. Check your connection or try again.',
      )
    } else {
      const status = error.response.status
      if (status === 401) {
        toastOnce(
          'auth',
          'Authentication failed',
          'Check your API key in Settings → API Key (or VITE_API_KEY) and reload.',
        )
      } else if (status === 403) {
        toastOnce('forbidden', 'Forbidden', 'You do not have access to this resource.')
      } else if (status >= 500) {
        toastOnce('server', 'Server error', `HTTP ${status} — check backend logs.`)
      }
    }
    // Keep the console breadcrumb for devtools debugging.
    const detailRaw = (error.response?.data as { detail?: unknown } | undefined)?.detail
    const detail = typeof detailRaw === 'string' ? detailRaw : undefined
    const message = detail ?? error.message ?? 'An error occurred'
    console.error('[API Error]', message)
    return Promise.reject(error)
  },
)

export default apiClient
