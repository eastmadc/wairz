import apiClient from './client'

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
    { params },
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
