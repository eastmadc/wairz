import apiClient from './client'

export interface AttackSurfaceEntry {
  id: string
  project_id: string
  firmware_id: string
  binary_path: string
  binary_name: string
  architecture: string | null
  file_size: number | null
  attack_surface_score: number
  score_breakdown: Record<string, unknown>
  is_setuid: boolean
  is_network_listener: boolean
  is_cgi_handler: boolean
  has_dangerous_imports: boolean
  dangerous_imports: string[]
  input_categories: string[]
  auto_findings_generated: boolean
  created_at: string
}

export interface AttackSurfaceSummary {
  total_binaries: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  top_categories: string[]
}

export interface AttackSurfaceScanResponse {
  entries: AttackSurfaceEntry[]
  summary: AttackSurfaceSummary
  cached: boolean
}

export async function getAttackSurface(
  projectId: string,
  params?: { min_score?: number; firmware_id?: string },
): Promise<AttackSurfaceEntry[]> {
  const { data } = await apiClient.get<AttackSurfaceEntry[]>(
    `/projects/${projectId}/attack-surface`,
    { params },
  )
  return data
}

export async function triggerAttackSurfaceScan(
  projectId: string,
  forceRescan = false,
): Promise<AttackSurfaceScanResponse> {
  const { data } = await apiClient.post<AttackSurfaceScanResponse>(
    `/projects/${projectId}/attack-surface/scan`,
    { force_rescan: forceRescan },
  )
  return data
}

export async function getAttackSurfaceEntry(
  projectId: string,
  entryId: string,
): Promise<AttackSurfaceEntry> {
  const { data } = await apiClient.get<AttackSurfaceEntry>(
    `/projects/${projectId}/attack-surface/${entryId}`,
  )
  return data
}
