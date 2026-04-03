import apiClient from './client'
import type { ComponentGraph } from '@/types'

export async function getComponentMap(
  projectId: string,
  firmwareId?: string | null,
): Promise<ComponentGraph> {
  const { data } = await apiClient.get<ComponentGraph>(
    `/projects/${projectId}/component-map`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}
