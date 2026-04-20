import apiClient from './client'
import type { FirmwareDetail, FirmwareMetadata, FirmwareSummary } from '@/types'

// Firmware uploads commonly run to MAX_UPLOAD_SIZE_MB (default 2 GB). On a
// 100 Mbps link a 2 GB upload is ~3 min of wall-clock; the default axios
// 30 s timeout in client.ts fires mid-upload and surfaces a fake
// "upload failed" while the backend is still streaming bytes to disk.
// Matches SECURITY_SCAN_TIMEOUT tier (10 min) used in findings.ts /
// exportImport.ts — same order of magnitude, same "backend is still
// doing work" UX contract. Applies to POST /firmware and
// POST /firmware/{id}/upload-rootfs (rootfs can be similarly large).
const UPLOAD_TIMEOUT = 600_000

export async function uploadFirmware(
  projectId: string,
  file: File,
  versionLabel?: string,
  onProgress?: (percent: number) => void,
): Promise<FirmwareSummary> {
  const form = new FormData()
  form.append('file', file)
  if (versionLabel) {
    form.append('version_label', versionLabel)
  }

  const { data } = await apiClient.post<FirmwareSummary>(
    `/projects/${projectId}/firmware`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: UPLOAD_TIMEOUT,
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

export async function listFirmware(
  projectId: string,
): Promise<FirmwareDetail[]> {
  const { data } = await apiClient.get<FirmwareDetail[]>(
    `/projects/${projectId}/firmware`,
  )
  return data
}

export async function getSingleFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.get<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
  )
  return data
}

export async function updateFirmware(
  projectId: string,
  firmwareId: string,
  data: { version_label?: string | null },
): Promise<FirmwareDetail> {
  const { data: result } = await apiClient.patch<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
    data,
  )
  return result
}

export async function deleteFirmware(
  projectId: string,
  firmwareId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/firmware/${firmwareId}`)
}

export async function unpackFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/unpack`,
  )
  return data
}

export async function uploadRootfs(
  projectId: string,
  firmwareId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<FirmwareDetail> {
  const form = new FormData()
  form.append('file', file)

  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/upload-rootfs`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: UPLOAD_TIMEOUT,
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

export async function getFirmwareMetadata(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareMetadata> {
  const { data } = await apiClient.get<FirmwareMetadata>(
    `/projects/${projectId}/firmware/${firmwareId}/metadata`,
  )
  return data
}
