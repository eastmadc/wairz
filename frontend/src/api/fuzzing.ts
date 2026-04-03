import apiClient from './client'
import type {
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingCrashDetail,
  FuzzingTargetAnalysis,
  FuzzingCampaignCreateRequest,
} from '@/types'

export async function analyzeTarget(
  projectId: string,
  path: string,
  firmwareId?: string | null,
): Promise<FuzzingTargetAnalysis> {
  const params: Record<string, string> = { path }
  if (firmwareId) params.firmware_id = firmwareId
  const { data } = await apiClient.get<FuzzingTargetAnalysis>(
    `/projects/${projectId}/fuzzing/analyze`,
    { params },
  )
  return data
}

export async function createCampaign(
  projectId: string,
  request: FuzzingCampaignCreateRequest,
  firmwareId?: string | null,
): Promise<FuzzingCampaign> {
  const { data } = await apiClient.post<FuzzingCampaign>(
    `/projects/${projectId}/fuzzing/campaigns`,
    request,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function startCampaign(
  projectId: string,
  campaignId: string,
): Promise<FuzzingCampaign> {
  const { data } = await apiClient.post<FuzzingCampaign>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}/start`,
  )
  return data
}

export async function stopCampaign(
  projectId: string,
  campaignId: string,
): Promise<FuzzingCampaign> {
  const { data } = await apiClient.post<FuzzingCampaign>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}/stop`,
  )
  return data
}

export async function listCampaigns(
  projectId: string,
): Promise<FuzzingCampaign[]> {
  const { data } = await apiClient.get<FuzzingCampaign[]>(
    `/projects/${projectId}/fuzzing/campaigns`,
  )
  return data
}

export async function getCampaign(
  projectId: string,
  campaignId: string,
): Promise<FuzzingCampaign> {
  const { data } = await apiClient.get<FuzzingCampaign>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}`,
  )
  return data
}

export async function listCrashes(
  projectId: string,
  campaignId: string,
): Promise<FuzzingCrash[]> {
  const { data } = await apiClient.get<FuzzingCrash[]>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}/crashes`,
  )
  return data
}

export async function getCrashDetail(
  projectId: string,
  campaignId: string,
  crashId: string,
): Promise<FuzzingCrashDetail> {
  const { data } = await apiClient.get<FuzzingCrashDetail>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}/crashes/${crashId}`,
  )
  return data
}

export async function triageCrash(
  projectId: string,
  campaignId: string,
  crashId: string,
): Promise<FuzzingCrash> {
  const { data } = await apiClient.post<FuzzingCrash>(
    `/projects/${projectId}/fuzzing/campaigns/${campaignId}/crashes/${crashId}/triage`,
  )
  return data
}
