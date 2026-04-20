import apiClient from './client'
import type {
  FunctionListResponse,
  ImportsResponse,
  DisassemblyResponse,
  DecompilationResponse,
  CleanedCodeResponse,
  BinaryInfoResponse,
} from '@/types'

// Binary analysis endpoints are backed by radare2 (list/imports/disasm/
// binary-info) and Ghidra headless (decompile/cleaned-code). Frontend
// timeouts derive from backend work ceilings + 20% grace per Rule #29:
//
//   Ghidra tier = 360_000 ms  ← 300 s (config.py:24 `ghidra_timeout`) × 1.2
//   radare2 tier = 150_000 ms ← 120 s (binary.py:1637 `communicate` timeout) × 1.25
//
// Previous values (180s Ghidra, 90s radare2) were derived from a stale
// "120s default" reference — ghidra_timeout was raised to 300 in config.py
// before the frontend was updated, so cold-cache decompile requests were
// failing on the client side while the backend kept working. Session
// 7e8dd7c3 research (backend-timeout-audit) surfaced the mismatch.
//
// Warm cache hits are instant; the tier values are for cold-cache worst
// case. Both derive from Rule #29's `frontend_ms = backend_s * 1200`
// formula — update the comment AND constant together when the backend
// config changes.
const GHIDRA_ANALYSIS_TIMEOUT = 360_000
const RADARE2_ANALYSIS_TIMEOUT = 150_000

export async function listFunctions(
  projectId: string,
  binaryPath: string,
): Promise<FunctionListResponse> {
  const { data } = await apiClient.get<FunctionListResponse>(
    `/projects/${projectId}/analysis/functions`,
    { params: { path: binaryPath }, timeout: RADARE2_ANALYSIS_TIMEOUT },
  )
  return data
}

export async function listImports(
  projectId: string,
  binaryPath: string,
): Promise<ImportsResponse> {
  const { data } = await apiClient.get<ImportsResponse>(
    `/projects/${projectId}/analysis/imports`,
    { params: { path: binaryPath }, timeout: RADARE2_ANALYSIS_TIMEOUT },
  )
  return data
}

export async function disassembleFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
  maxInstructions: number = 100,
): Promise<DisassemblyResponse> {
  const { data } = await apiClient.get<DisassemblyResponse>(
    `/projects/${projectId}/analysis/disasm`,
    {
      params: { path: binaryPath, function: functionName, max_instructions: maxInstructions },
      timeout: RADARE2_ANALYSIS_TIMEOUT,
    },
  )
  return data
}

export async function decompileFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
): Promise<DecompilationResponse> {
  const { data } = await apiClient.get<DecompilationResponse>(
    `/projects/${projectId}/analysis/decompile`,
    { params: { path: binaryPath, function: functionName }, timeout: GHIDRA_ANALYSIS_TIMEOUT },
  )
  return data
}

export async function fetchCleanedCode(
  projectId: string,
  binaryPath: string,
  functionName: string,
): Promise<CleanedCodeResponse> {
  const { data } = await apiClient.get<CleanedCodeResponse>(
    `/projects/${projectId}/analysis/cleaned-code`,
    { params: { path: binaryPath, function: functionName }, timeout: GHIDRA_ANALYSIS_TIMEOUT },
  )
  return data
}

export async function getBinaryInfo(
  projectId: string,
  binaryPath: string,
): Promise<BinaryInfoResponse> {
  const { data } = await apiClient.get<BinaryInfoResponse>(
    `/projects/${projectId}/analysis/binary-info`,
    { params: { path: binaryPath }, timeout: RADARE2_ANALYSIS_TIMEOUT },
  )
  return data
}

