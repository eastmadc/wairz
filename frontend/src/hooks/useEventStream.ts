import { useState, useEffect, useRef } from 'react'
import { apiUrl } from '@/api/config'

export interface EventStreamOptions {
  /** Event types to subscribe to. Omit to receive all types. */
  types?: string[]
  /** Whether the stream is enabled (default true). Set false to disconnect. */
  enabled?: boolean
}

export interface EventStreamResult<T> {
  /** The most recently received event, or null if none yet. */
  lastEvent: T | null
  /** Whether the EventSource is currently connected. */
  connected: boolean
}

/**
 * React hook that connects to the SSE event stream for a project.
 *
 * Usage:
 *   const { lastEvent, connected } = useEventStream<MyEvent>(projectId, {
 *     types: ['unpacking', 'emulation'],
 *   })
 *
 * The hook manages EventSource lifecycle: connects on mount (or when
 * projectId/types change), disconnects on unmount or when enabled=false.
 */
export function useEventStream<T = Record<string, unknown>>(
  projectId: string | undefined,
  options: EventStreamOptions = {},
): EventStreamResult<T> {
  const { types, enabled = true } = options
  const [lastEvent, setLastEvent] = useState<T | null>(null)
  const [connected, setConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Stable serialization of types for dependency tracking
  const typesKey = types ? types.sort().join(',') : ''

  useEffect(() => {
    if (!projectId || !enabled) {
      setConnected(false)
      return
    }

    let url = apiUrl(`/api/v1/projects/${projectId}/events`)
    if (typesKey) {
      url += `?types=${encodeURIComponent(typesKey)}`
    }

    const es = new EventSource(url)
    eventSourceRef.current = es

    es.onopen = () => {
      setConnected(true)
    }

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as T
        setLastEvent(data)
      } catch {
        // Ignore non-JSON messages (keepalive pings are comments, not events)
      }
    }

    es.onerror = () => {
      setConnected(false)
      // EventSource will automatically attempt to reconnect
    }

    return () => {
      es.close()
      eventSourceRef.current = null
      setConnected(false)
    }
  }, [projectId, typesKey, enabled])

  return { lastEvent, connected }
}
