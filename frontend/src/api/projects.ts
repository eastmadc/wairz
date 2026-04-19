import apiClient from './client'
import type { Project, ProjectDetail } from '@/types'

// Backend now returns a Page envelope `{ items, total, offset, limit }`
// for list endpoints.  Callers of ``listProjects()`` still receive a
// ``Project[]`` to preserve backward-compat with every existing page.
// Any new caller that wants the total can use ``listProjectsPage()``.
interface PageEnvelope<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

function unwrap<T>(data: PageEnvelope<T> | T[]): T[] {
  return Array.isArray(data) ? data : (data?.items ?? [])
}

export async function listProjects(): Promise<Project[]> {
  const { data } = await apiClient.get<PageEnvelope<Project> | Project[]>('/projects')
  return unwrap(data)
}

export async function listProjectsPage(
  params?: { limit?: number; offset?: number },
): Promise<PageEnvelope<Project>> {
  const { data } = await apiClient.get<PageEnvelope<Project>>('/projects', { params })
  return data
}

export async function getProject(id: string): Promise<ProjectDetail> {
  const { data } = await apiClient.get<ProjectDetail>(`/projects/${id}`)
  return data
}

export async function createProject(params: {
  name: string
  description?: string
}): Promise<ProjectDetail> {
  const { data } = await apiClient.post<ProjectDetail>('/projects', params)
  return data
}

export async function deleteProject(id: string): Promise<void> {
  await apiClient.delete(`/projects/${id}`)
}
