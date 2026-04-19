import { appendApiKey } from './client'

export function buildTerminalWebSocketURL(projectId: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return appendApiKey(
    `${proto}//${host}/api/v1/projects/${projectId}/terminal/ws`,
  )
}
