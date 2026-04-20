import apiClient from './client'

// POST /tools/run is a generic MCP-tool dispatcher. The set of
// whitelisted tools includes long-running operations — decompile_function
// (30-120 s Ghidra), check_all_binary_protections (walks every ELF,
// can hit minutes), scan_with_yara, generate_sbom, etc. The default
// axios 30 s timeout in client.ts fires while a legitimate tool is
// still executing and surfaces a fake "tool failed" to the UI.
// Matches SECURITY_SCAN_TIMEOUT tier used by sibling files — the
// worst-case tool latency here is the same order of magnitude as a
// full security scan.
const TOOL_EXECUTION_TIMEOUT = 600_000

export interface ToolRunResponse {
  tool: string
  output: string
  success: boolean
}

export interface ToolInfo {
  name: string
  description: string
  input_schema: Record<string, unknown>
}

export interface ToolListResponse {
  tools: ToolInfo[]
  count: number
}

/**
 * Execute an MCP tool via the REST bridge.
 *
 * @param projectId - UUID of the project
 * @param toolName  - Registered MCP tool name (e.g. "check_binary_protections")
 * @param input     - Tool input parameters matching the tool's JSON Schema
 * @param firmwareId - Optional firmware UUID (defaults to most recent)
 */
export async function runTool(
  projectId: string,
  toolName: string,
  input: Record<string, unknown> = {},
  firmwareId?: string,
): Promise<ToolRunResponse> {
  const params: Record<string, string> = {}
  if (firmwareId) {
    params.firmware_id = firmwareId
  }
  const { data } = await apiClient.post<ToolRunResponse>(
    `/projects/${projectId}/tools/run`,
    { tool_name: toolName, input },
    { params, timeout: TOOL_EXECUTION_TIMEOUT },
  )
  return data
}

/**
 * List all MCP tools available via the REST bridge.
 *
 * Returns tool names, descriptions, and input schemas for every
 * whitelisted (read-only) tool.
 */
export async function listTools(
  projectId: string,
): Promise<ToolListResponse> {
  const { data } = await apiClient.get<ToolListResponse>(
    `/projects/${projectId}/tools`,
  )
  return data
}
