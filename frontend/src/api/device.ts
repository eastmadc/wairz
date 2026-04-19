import apiClient from './client'
import type {
  BridgeStatus,
  DeviceInfo,
  DeviceDetail,
  DumpStatus,
  ImportResult,
} from '@/types/device'

export async function getDeviceBridgeStatus(
  projectId: string,
): Promise<BridgeStatus> {
  const { data } = await apiClient.get<BridgeStatus>(
    `/projects/${projectId}/device/status`,
  )
  return data
}

export async function listDevices(
  projectId: string,
): Promise<DeviceInfo[]> {
  const { data } = await apiClient.get<{ devices: DeviceInfo[] }>(
    `/projects/${projectId}/device/devices`,
  )
  return data.devices
}

export async function getDeviceInfo(
  projectId: string,
  deviceId: string,
): Promise<DeviceDetail> {
  const { data } = await apiClient.get<DeviceDetail>(
    `/projects/${projectId}/device/devices/${deviceId}/info`,
  )
  return data
}

// startDump() kicks off an ADB dump via the device bridge. The trigger
// call itself is typically fast, but when the bridge is slow to
// enumerate partitions or the device is mid-reboot the initial POST can
// stall past the default axios 30 s and surface a fake "failed to
// start dump" while the bridge eventually succeeds and the actual dump
// begins. 5 min matches the HASH_SCAN_TIMEOUT tier used by findings.ts
// for hashlookup-style bridge calls (b437095).
const DEVICE_BRIDGE_TIMEOUT = 300_000

export async function startDump(
  projectId: string,
  deviceId: string,
  partitions: string[],
): Promise<DumpStatus> {
  const { data } = await apiClient.post<DumpStatus>(
    `/projects/${projectId}/device/dump`,
    { device_id: deviceId, partitions },
    { timeout: DEVICE_BRIDGE_TIMEOUT },
  )
  return data
}

export async function getDumpStatus(
  projectId: string,
): Promise<DumpStatus> {
  const { data } = await apiClient.get<DumpStatus>(
    `/projects/${projectId}/device/dump/status`,
  )
  return data
}

export async function cancelDump(
  projectId: string,
): Promise<void> {
  await apiClient.post(`/projects/${projectId}/device/dump/cancel`)
}

export async function importDump(
  projectId: string,
  deviceId: string,
  versionLabel?: string,
): Promise<ImportResult> {
  const { data } = await apiClient.post<ImportResult>(
    `/projects/${projectId}/device/import`,
    { device_id: deviceId, version_label: versionLabel },
  )
  return data
}
