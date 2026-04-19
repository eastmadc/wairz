export interface BridgeStatus {
  connected: boolean
  bridge_host: string | null
  bridge_port: number | null
  error: string | null
}

/**
 * Acquisition mode emitted by the device bridge
 * (scripts/wairz-device-bridge.py). Listed modes are EXACTLY what the bridge
 * currently reports — do not add speculative values like 'edl' or 'fastboot'.
 * Backend keeps the field loosely typed (`str | None`) for forward compat;
 * the frontend narrows it here, with a `null` / `undefined` fallback for
 * ADB devices that don't populate these fields.
 */
export type DeviceMode = 'adb' | 'brom' | 'preloader'

export interface DeviceInfo {
  serial: string
  model: string | null
  device: string | null
  transport_id: string | null
  state: string
  /**
   * Populated for MediaTek BROM/preloader devices. ADB devices return
   * null/undefined — the backend `DeviceInfo` schema makes all three
   * acquisition-mode fields Optional (default None).
   */
  mode?: DeviceMode | null
  available?: boolean | null
  error?: string | null
}

export interface PartitionInfo {
  name: string
  size: number | null
}

export interface DeviceDetail {
  device: DeviceInfo
  getprop: Record<string, string>
  partitions: string[]
  partition_sizes: PartitionInfo[]
  device_metadata: Record<string, unknown> | null
  /**
   * MediaTek chipset identifier (e.g. "MT6765") for BROM/preloader devices.
   * ADB devices surface the same info via getprop['ro.hardware.chipname']
   * instead, and leave this null.
   */
  chipset?: string | null
}

export interface PartitionStatus {
  partition: string
  status: 'pending' | 'active' | 'complete' | 'failed' | 'skipped'
  bytes_written: number
  total_bytes: number | null
  progress_percent: number | null
  throughput_mbps: number | null
  size: number | null
  error: string | null
  path: string | null
}

export interface DumpStatus {
  status: 'idle' | 'dumping' | 'complete' | 'partial' | 'failed' | 'cancelled'
  device_id: string | null
  partitions: PartitionStatus[]
  error: string | null
}

export interface ImportResult {
  firmware_id: string
  device_metadata: Record<string, unknown> | null
  message: string
}
