export interface BridgeStatus {
  connected: boolean
  bridge_host: string | null
  bridge_port: number | null
  error: string | null
}

export interface DeviceInfo {
  serial: string
  model: string | null
  device: string | null
  transport_id: string | null
  state: string
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
