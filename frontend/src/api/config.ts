/**
 * Frontend-side API origin + URL helper.
 *
 * Centralises the `VITE_API_URL || ''` read so every raw URL site
 * (EventSource, anchor hrefs for downloads, WS URLs where applicable)
 * uses the same base.  Axios itself is configured with `baseURL:
 * '/api/v1'` in `client.ts` — this helper is for things that bypass
 * axios (SSE, file downloads as <a href>, future cross-origin deploys).
 *
 * Contract: `path` should start with `/`.  Missing leading `/` is
 * tolerated — we insert one — but callers should prefer the explicit
 * form for readability.
 */

export const API_BASE: string = (import.meta.env.VITE_API_URL as string | undefined) || ''

export function apiUrl(path: string): string {
  return `${API_BASE}${path.startsWith('/') ? path : '/' + path}`
}
