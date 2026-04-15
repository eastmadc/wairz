/**
 * TypeScript types for APK security scan findings.
 *
 * These types mirror the Pydantic response schemas in
 * backend/app/routers/apk_scan.py for all three scan phases:
 *   - Phase 1: Manifest security checks (18 MobSF-equivalent)
 *   - Phase 2a: Bytecode insecure API pattern detection
 *   - Phase 2b: SAST via jadx + mobsfscan pipeline
 */

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/** Firmware metadata context attached to scan responses. */
export interface FirmwareContextResponse {
  device_model: string | null
  manufacturer: string | null
  android_version: string | null
  api_level: number | null
  security_patch: string | null
  architecture: string | null
  partition: string | null
  firmware_filename: string | null
  bootloader_state: string | null
  is_priv_app: boolean
  is_system_app: boolean
  is_vendor_app: boolean
}

/** Severity levels for APK scan findings. */
export type ApkScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Confidence levels for manifest findings. */
export type ApkScanConfidence = 'high' | 'medium' | 'low'

// ---------------------------------------------------------------------------
// Phase 1: Manifest scan types
// ---------------------------------------------------------------------------

/** A single manifest security finding. */
export interface ManifestFindingResponse {
  check_id: string
  title: string
  description: string
  severity: string
  evidence: string
  cwe_ids: string[]
  confidence: string
}

/** Summary statistics for a manifest scan. */
export interface ManifestScanSummary {
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

/** Confidence breakdown for scan findings. */
export interface ConfidenceSummary {
  high: number
  medium: number
  low: number
}

/** Full response for a manifest security scan. */
export interface ManifestScanResponse {
  package: string
  findings: ManifestFindingResponse[]
  summary: ManifestScanSummary
  confidence_summary: ConfidenceSummary
  is_priv_app: boolean
  is_platform_signed: boolean
  severity_reduced: boolean
  reduced_check_ids: string[]
  from_cache: boolean
  elapsed_ms: number | null
  error: string | null
  firmware_context: FirmwareContextResponse | null
}

// ---------------------------------------------------------------------------
// Phase 2a: Bytecode scan types
// ---------------------------------------------------------------------------

/** A single location where a bytecode pattern was detected. */
export interface BytecodeFindingLocation {
  caller_class: string | null
  caller_method: string | null
  target: string | null
  string_value: string | null
  using_class: string | null
  using_method: string | null
  dangerous_class: string | null
}

/** A single bytecode security finding. */
export interface BytecodeFindingResponse {
  pattern_id: string
  title: string
  description: string
  severity: string
  confidence: string
  cwe_ids: string[]
  category: string
  locations: Record<string, unknown>[]
  total_occurrences: number
}

/** Summary statistics for a bytecode scan. */
export interface BytecodeScanSummary {
  total_findings: number
  by_severity: Record<string, number>
  by_category: Record<string, number>
  by_confidence: Record<string, number>
}

/** Full response for a bytecode scan. */
export interface BytecodeScanResponse {
  package: string
  findings: BytecodeFindingResponse[]
  summary: BytecodeScanSummary
  elapsed_seconds: number
  dex_count: number
  from_cache: boolean
  error: string | null
  firmware_context: FirmwareContextResponse | null
}

// ---------------------------------------------------------------------------
// Phase 2b: SAST scan types
// ---------------------------------------------------------------------------

/** A single SAST finding from mobsfscan. */
export interface SastFindingResponse {
  rule_id: string
  title: string
  description: string
  severity: string
  file_path: string | null
  source_file: string | null
  line_number: number | null
  cwe_ids: string[]
  owasp_mobile: string
  masvs: string
}

/** Pipeline timing breakdown. */
export interface SastScanTimingResponse {
  total_elapsed_ms: number
  jadx_elapsed_ms: number
  mobsfscan_elapsed_ms: number
}

/** Summary statistics for a SAST scan. */
export interface SastScanSummary {
  total_findings: number
  by_severity: Record<string, number>
  files_scanned: number
  normalized_findings: number
  persisted_count: number
}

/** Full response for a SAST (jadx + mobsfscan) scan. */
export interface SastScanResponse {
  success: boolean
  findings: SastFindingResponse[]
  summary: SastScanSummary
  timing: SastScanTimingResponse
  cached: boolean
  error: string | null
  firmware_context: FirmwareContextResponse | null
}

// ---------------------------------------------------------------------------
// Combined scan result (all phases)
// ---------------------------------------------------------------------------

/** Combined result from running all three scan phases concurrently. */
export interface ApkFullScanResult {
  manifest: ManifestScanResponse | null
  bytecode: BytecodeScanResponse | null
  sast: SastScanResponse | null
}

/** Options for the combined scan. */
export interface ApkScanOptions {
  persistFindings?: boolean
  minSeverity?: string
  forceRescan?: boolean
  timeout?: number
}
