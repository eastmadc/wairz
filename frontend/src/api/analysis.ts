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
// binary-info) and Ghidra headless (decompile/cleaned-code). Cold-cache
// radare2 `aaa` analysis on a large binary takes 10-30 s; Ghidra
// decompilation takes 30-120 s per GHIDRA_TIMEOUT in config.py. Warm
// cache hits are instant, but the first request on a fresh binary will
// routinely exceed the default axios 30 s timeout in client.ts and
// surface a fake "decompile failed" / "radare2 failed" while the
// analysis actually completes and populates the cache. The Ghidra tier
// (3 min) covers the 120 s server-side budget plus margin; the radare2
// tier (90 s) covers the 30 s worst-case `aaa` plus margin.
const GHIDRA_ANALYSIS_TIMEOUT = 180_000
const RADARE2_ANALYSIS_TIMEOUT = 90_000

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

