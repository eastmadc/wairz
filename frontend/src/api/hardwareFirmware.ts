import apiClient from './client'

export interface HardwareFirmwareBlob {
  id: string
  firmware_id: string
  blob_path: string
  partition: string | null
  blob_sha256: string
  file_size: number
  category: string
  vendor: string | null
  format: string
  version: string | null
  signed: string
  signature_algorithm: string | null
  cert_subject: string | null
  chipset_target: string | null
  driver_references: string[] | null
  sbom_component_id?: string | null
  metadata: Record<string, unknown>
  detection_source: string
  detection_confidence: string
  created_at: string
}

export interface HardwareFirmwareListResponse {
  blobs: HardwareFirmwareBlob[]
  total: number
}

export interface FirmwareCveMatch {
  id: string
  blob_id: string | null
  cve_id: string
  severity: string
  cvss_score: number | null
  description: string | null
  match_confidence: string | null
  match_tier: string | null
  resolution_status: string
  created_at: string | null
}

export interface FirmwareEdge {
  driver_path: string
  firmware_name: string
  firmware_blob_path: string | null
  source: string
}

export interface FirmwareEdgesResponse {
  edges: FirmwareEdge[]
  kmod_drivers: number
  dtb_sources: number
  unresolved_count: number
}

export interface FirmwareDriver {
  driver_path: string
  format: string
  firmware_deps: string[]
  firmware_blobs: string[]
  total: number
}

export interface FirmwareDriversListResponse {
  drivers: FirmwareDriver[]
  total: number
}

export async function listHardwareFirmware(
  projectId: string,
  filters?: { category?: string; vendor?: string; signedOnly?: boolean; firmwareId?: string | null },
): Promise<HardwareFirmwareListResponse> {
  const params: Record<string, unknown> = {}
  if (filters?.category) params.category = filters.category
  if (filters?.vendor) params.vendor = filters.vendor
  if (filters?.signedOnly) params.signed_only = true
  if (filters?.firmwareId) params.firmware_id = filters.firmwareId
  const { data } = await apiClient.get<HardwareFirmwareListResponse>(
    `/projects/${projectId}/hardware-firmware`,
    { params },
  )
  return data
}

export async function getHardwareFirmwareBlob(
  projectId: string,
  blobId: string,
  firmwareId?: string | null,
): Promise<HardwareFirmwareBlob> {
  const { data } = await apiClient.get<HardwareFirmwareBlob>(
    `/projects/${projectId}/hardware-firmware/${blobId}`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function getHardwareFirmwareCves(
  projectId: string,
  blobId: string,
  firmwareId?: string | null,
): Promise<FirmwareCveMatch[]> {
  const { data } = await apiClient.get<FirmwareCveMatch[]>(
    `/projects/${projectId}/hardware-firmware/${blobId}/cves`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export interface CveMatchRunResult {
  count: number           // distinct CVE IDs across all tiers
  rows: number            // total persisted match rows (cartesian kernel_cve × kmod included)
  hw_firmware_cves: number
  kernel_cves: number
  kernel_module_rows: number
}

export async function runCveMatch(
  projectId: string,
  options?: { forceRescan?: boolean; firmwareId?: string | null },
): Promise<CveMatchRunResult> {
  const params: Record<string, unknown> = {}
  if (options?.forceRescan) params.force_rescan = true
  if (options?.firmwareId) params.firmware_id = options.firmwareId
  const { data } = await apiClient.post<CveMatchRunResult>(
    `/projects/${projectId}/hardware-firmware/cve-match`,
    null,
    { params },
  )
  return data
}

export async function getFirmwareEdges(
  projectId: string,
  firmwareId?: string | null,
): Promise<FirmwareEdgesResponse> {
  const { data } = await apiClient.get<FirmwareEdgesResponse>(
    `/projects/${projectId}/hardware-firmware/firmware-edges`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function getFirmwareDrivers(
  projectId: string,
  firmwareId?: string | null,
): Promise<FirmwareDriversListResponse> {
  const { data } = await apiClient.get<FirmwareDriversListResponse>(
    `/projects/${projectId}/hardware-firmware/drivers`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}
