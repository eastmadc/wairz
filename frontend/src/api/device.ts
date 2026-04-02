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

export async function startDump(
  projectId: string,
  deviceId: string,
  partitions: string[],
): Promise<DumpStatus> {
  const { data } = await apiClient.post<DumpStatus>(
    `/projects/${projectId}/device/dump`,
    { device_id: deviceId, partitions },
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
