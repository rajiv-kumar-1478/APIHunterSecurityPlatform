import {
  apiFetch,
  getErrorMessage,
  getResponseMessage,
  parseJsonResponse,
  parseResponseBody,
} from "@/lib/api-client";

export interface SecurityPosture {
  totalRepositoriesMonitored: number;
  highestRepositoryRiskScore: number;
  overallSeverity: string;
  openFindingsCount: number;
  criticalFindingsCount: number;
  highFindingsCount: number;
  validatedCredentialsCount: number;
  calculatedAtUtc: string;
}

export interface AlertingStatus {
  enabled: boolean;
  cooldownMinutes: number;
  highSeverityThreshold: number;
  criticalSeverityThreshold: number;
  riskJumpThreshold: number;
}

export interface RiskFactor {
  code: string;
  description: string;
  weight: number;
}

export interface SecurityFinding {
  id: string;
  repositoryId: string;
  snapshotId?: string;
  findingFingerprint: string;
  findingType: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  description: string;
  riskScore: number;
  riskFactorBreakdownJson: string;
  lifecycleVersion: number;
  resolvedAtUtc?: string;
  resolvedByUserId?: string;
  resolutionReason?: string;
  firstObservedAtUtc: string;
  lastObservedAtUtc: string;
  createdAtUtc: string;
}

export interface FindingEvidence {
  id: string;
  findingId: string;
  evidenceType: string;
  discoverySource: string;
  evidenceFingerprint: string;
  snapshotId?: string;
  snapshotFileId?: string;
  candidateId?: string;
  validationResultId?: string;
  intelligenceNodeId?: string;
  intelligenceEdgeId?: string;
  evidenceReference: string;
  safeEvidenceJson: string;
  createdAtUtc: string;
}

export interface StatusHistory {
  id: string;
  findingId: string;
  fromStatus?: string;
  toStatus: string;
  changedByUserId?: string;
  reason: string;
  metadataJson: string;
  createdAtUtc: string;
}

export interface PagedResult<T> {
  items: T[];
  totalCount: number;
  page: number;
  pageSize: number;
}

export interface IntelligenceNode {
  id: string;
  repositoryId?: string;
  nodeType: string;
  name: string;
  label: string;
  discoverySource: string;
  relatedEntityId?: string;
  metadataJson: string;
  createdAtUtc: string;
}

export interface IntelligenceEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  edgeType: string;
  discoverySource: string;
  weight: number;
  metadataJson: string;
  createdAtUtc: string;
}

export interface GraphData {
  nodes: IntelligenceNode[];
  edges: IntelligenceEdge[];
}

export function fetchWithAuth(path: string, options: RequestInit = {}): Promise<Response> {
  return apiFetch(path, options);
}

export async function getSecurityPosture(): Promise<SecurityPosture | null> {
  try {
    const res = await fetchWithAuth("/api/v1/security-center/posture");
    if (!res.ok) return null;
    return await parseJsonResponse<SecurityPosture>(res);
  } catch {
    return null;
  }
}

export async function getAlertingStatus(): Promise<AlertingStatus | null> {
  try {
    const res = await fetchWithAuth("/api/v1/security-center/alerting-status");
    if (!res.ok) return null;
    return await parseJsonResponse<AlertingStatus>(res);
  } catch {
    return null;
  }
}

export async function getFindings(params: {
  repositoryId?: string;
  severity?: string;
  status?: string;
  findingType?: string;
  page?: number;
  pageSize?: number;
}): Promise<PagedResult<SecurityFinding>> {
  const query = new URLSearchParams();
  if (params.repositoryId) query.set("repositoryId", params.repositoryId);
  if (params.severity) query.set("severity", params.severity);
  if (params.status) query.set("status", params.status);
  if (params.findingType) query.set("findingType", params.findingType);
  query.set("page", String(params.page ?? 1));
  query.set("pageSize", String(params.pageSize ?? 20));

  const fallback = { items: [], totalCount: 0, page: 1, pageSize: 20 };
  const res = await fetchWithAuth(`/api/v1/findings?${query.toString()}`);
  if (!res.ok) return fallback;
  return (await parseJsonResponse<PagedResult<SecurityFinding>>(res)) ?? fallback;
}

export async function getFindingEvidence(findingId: string): Promise<FindingEvidence[]> {
  try {
    const res = await fetchWithAuth(`/api/v1/findings/${findingId}/evidence`);
    if (!res.ok) return [];
    return (await parseJsonResponse<FindingEvidence[]>(res)) ?? [];
  } catch {
    return [];
  }
}

export async function getFindingHistory(findingId: string): Promise<StatusHistory[]> {
  try {
    const res = await fetchWithAuth(`/api/v1/findings/${findingId}/history`);
    if (!res.ok) return [];
    return (await parseJsonResponse<StatusHistory[]>(res)) ?? [];
  } catch {
    return [];
  }
}

export async function updateFindingStatus(
  findingId: string,
  newStatus: string,
  expectedLifecycleVersion: number,
  reason: string
): Promise<{ success: boolean; message: string }> {
  try {
    const res = await fetchWithAuth(`/api/v1/findings/${findingId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        newStatus,
        expectedLifecycleVersion,
        reason,
      }),
    });

    const body = await parseResponseBody(res);
    if (!res.ok) {
      return {
        success: false,
        message: getResponseMessage(body, "Failed to update finding status."),
      };
    }
    return {
      success: true,
      message: getResponseMessage(body, "Status updated successfully."),
    };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Network error.") };
  }
}

export async function getSecurityGraph(repositoryId?: string): Promise<GraphData> {
  try {
    const query = repositoryId ? `?repositoryId=${encodeURIComponent(repositoryId)}` : "";
    const res = await fetchWithAuth(`/api/v1/intelligence/graph${query}`);
    if (!res.ok) return { nodes: [], edges: [] };
    return (await parseJsonResponse<GraphData>(res)) ?? { nodes: [], edges: [] };
  } catch {
    return { nodes: [], edges: [] };
  }
}

export interface ToolExecutionReceiptDto {
  toolKey: string;
  version: string;
  executable?: string;
  containerImageRepository?: string;
  containerImageDigest?: string;
  profile: number | string;
  phase: number | string;
  status: number | string;
  startedAtUtc: string;
  completedAtUtc: string;
  durationMs: number;
  outputSizeBytes: number;
  candidatesParsed: number;
  findingsCreated: number;
  findingsUpdated: number;
  failureReason?: string;
  failureClassification?: number | string;
}

export interface ScanExecutionReceiptDto {
  jobId: string;
  profile: number | string;
  finalJobStatus: number | string;
  startedAtUtc: string;
  completedAtUtc: string;
  toolReceipts: ToolExecutionReceiptDto[];
  totalFindingsCreated: number;
  totalFindingsUpdated: number;
  summary: string;
}

export interface ScanJobDetailDto {
  id: string;
  repositoryId?: string;
  repositoryName?: string;
  targetId?: string;
  targetName?: string;
  targetUrl: string;
  scanProfile: number | string;
  status: number | string;
  providerKey: string;
  correlationId: string;
  progressPercentage: number;
  currentPhase?: string;
  currentTool?: string;
  totalFindingsCount: number;
  createdAtUtc: string;
  startedAtUtc?: string;
  completedAtUtc?: string;
  cancelledAtUtc?: string;
  failureReason?: string;
  retryOfJobId?: string;
  version: number;
  executionReceipt?: ScanExecutionReceiptDto;
}

export interface CreateScanJobParams {
  repositoryId?: string;
  targetId?: string;
  targetUrl: string;
  scanProfile: number | string;
  providerKey?: string;
}

export interface ScanJobMutationResult {
  success: boolean;
  data?: ScanJobDetailDto;
  message?: string;
}

export async function getScanJobs(status?: string): Promise<ScanJobDetailDto[]> {
  try {
    const query = status ? `?status=${encodeURIComponent(status)}` : "";
    const res = await fetchWithAuth(`/api/v1/security/scans/jobs${query}`);
    if (!res.ok) return [];
    return (await parseJsonResponse<ScanJobDetailDto[]>(res)) ?? [];
  } catch {
    return [];
  }
}

export async function getScanJobDetail(jobId: string): Promise<ScanJobDetailDto | null> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/scans/jobs/${jobId}`);
    if (!res.ok) return null;
    return await parseJsonResponse<ScanJobDetailDto>(res);
  } catch {
    return null;
  }
}

export async function getScanJobReceipt(jobId: string): Promise<ScanExecutionReceiptDto | null> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/scans/jobs/${jobId}/receipt`);
    if (!res.ok) return null;
    return await parseJsonResponse<ScanExecutionReceiptDto>(res);
  } catch {
    return null;
  }
}

export async function createScanJob(params: CreateScanJobParams): Promise<ScanJobMutationResult> {
  try {
    const res = await fetchWithAuth("/api/v1/security/scans/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });
    const body = await parseResponseBody(res);
    if (!res.ok) {
      return {
        success: false,
        message: getResponseMessage(body, "Failed to create scan job."),
      };
    }
    return { success: true, data: body as ScanJobDetailDto };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Network error.") };
  }
}

export async function retryScanJob(jobId: string): Promise<ScanJobMutationResult> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/scans/jobs/${jobId}/retry`, {
      method: "POST",
    });
    const body = await parseResponseBody(res);
    if (!res.ok) {
      return {
        success: false,
        message: getResponseMessage(body, "Failed to retry scan job."),
      };
    }
    return { success: true, data: body as ScanJobDetailDto };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Network error.") };
  }
}

export async function cancelScanJob(
  jobId: string,
  reason: string,
  expectedVersion: number,
): Promise<ScanJobMutationResult> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/scans/jobs/${jobId}/cancel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason, expectedVersion }),
    });
    const body = await parseResponseBody(res);
    if (!res.ok) {
      return {
        success: false,
        message: getResponseMessage(body, "Failed to cancel scan job."),
      };
    }
    return { success: true, data: body as ScanJobDetailDto };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Network error.") };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 9 Continuous Scan Campaigns & Observability
// ─────────────────────────────────────────────────────────────────────────────

export interface ScanCampaignDto {
  id: string;
  tenantId: string;
  repositoryId: string;
  repositoryName?: string;
  securityTargetId: string;
  securityTargetName?: string;
  targetUrl?: string;
  name: string;
  description?: string;
  status: "Active" | "Paused" | "AutoPaused" | "Archived";
  scanProfile: string | number;
  scheduleType: string | number;
  cronExpression?: string;
  intervalDuration?: string;
  timeZoneId: string;
  concurrencyPolicy: string | number;
  scheduleVersion: number;
  nextRunUtc?: string;
  lastRunUtc?: string;
  lastScanJobId?: string;
  totalRunsCount: number;
  consecutiveFailuresCount: number;
  maxConsecutiveFailures: number;
  autoPauseOnConsecutiveFailures: boolean;
  createdAtUtc: string;
  updatedAtUtc?: string;
}

export interface CampaignOperationalHealthDto {
  tenantId: string;
  status: "Healthy" | "Degraded" | "Unavailable" | "NotConfigured" | "FailClosed";
  statusReason: string;
  totalCampaigns: number;
  activeCampaigns: number;
  pausedCampaigns: number;
  autoPausedCampaigns: number;
  overdueCampaignsCount: number;
  lastSchedulerTickUtc?: string;
  schedulerWorkerAlive: boolean;
  metrics24h: CampaignWindowMetricsDto;
  metrics7d: CampaignWindowMetricsDto;
  evaluatedAtUtc: string;
}

export interface CampaignWindowMetricsDto {
  window: string;
  totalEvaluations: number;
  dispatchedCount: number;
  skippedCount: number;
  completedScansCount: number;
  failedScansCount: number;
  recoveredStuckCount: number;
  successRatePercentage: number;
  averageScanDurationSeconds: number;
}

export interface CampaignExecutionHistoryEntryDto {
  auditLogId: string;
  campaignId: string;
  campaignName: string;
  tenantId: string;
  decision: string;
  triggerSource: string;
  scheduleVersion: number;
  evaluatedAtUtc: string;
  reason: string;
  occurrenceKey?: string;
  scanJobId?: string;
  scanJobStatus?: string;
  targetUrl?: string;
  scanProfile?: string;
  scanStartedAtUtc?: string;
  scanCompletedAtUtc?: string;
  scanDurationSeconds?: number;
  totalFindingsCount?: number;
  scanFailureReason?: string;
}

export interface CampaignDiagnosticsDto {
  campaignId: string;
  campaignName: string;
  status: string;
  consecutiveFailuresCount: number;
  maxConsecutiveFailures: number;
  autoPauseOnConsecutiveFailures: boolean;
  autoPauseReason?: string;
  autoPausedAtUtc?: string;
  scheduleVersion: number;
  nextRunUtc?: string;
  lastRunUtc?: string;
  isOverdue: boolean;
  overdueBy?: string;
  recentFailureStreak: Array<{
    scanJobId?: string;
    timestampUtc: string;
    failureType: string;
    reason: string;
  }>;
  recentRecoveries: Array<{
    auditLogId: string;
    scanJobId?: string;
    recoveredAtUtc: string;
    triggerSource: string;
    reason: string;
    metadataJson?: string;
  }>;
}

export async function getCampaigns(status?: string): Promise<ScanCampaignDto[]> {
  try {
    const query = status ? `?status=${encodeURIComponent(status)}` : "";
    const res = await fetchWithAuth(`/api/v1/security/campaigns${query}`);
    if (!res.ok) return [];
    return (await parseJsonResponse<ScanCampaignDto[]>(res)) ?? [];
  } catch {
    return [];
  }
}

export async function getCampaignHealth(): Promise<CampaignOperationalHealthDto | null> {
  try {
    const res = await fetchWithAuth("/api/v1/security/campaigns/health");
    if (!res.ok) return null;
    return await parseJsonResponse<CampaignOperationalHealthDto>(res);
  } catch {
    return null;
  }
}

export async function getCampaignHistory(
  campaignId: string,
  page = 1,
  pageSize = 50,
): Promise<CampaignExecutionHistoryEntryDto[]> {
  try {
    const res = await fetchWithAuth(
      `/api/v1/security/campaigns/${campaignId}/history?page=${page}&pageSize=${pageSize}`,
    );
    if (!res.ok) return [];
    return (await parseJsonResponse<CampaignExecutionHistoryEntryDto[]>(res)) ?? [];
  } catch {
    return [];
  }
}

export async function getCampaignDiagnostics(campaignId: string): Promise<CampaignDiagnosticsDto | null> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/campaigns/${campaignId}/diagnostics`);
    if (!res.ok) return null;
    return await parseJsonResponse<CampaignDiagnosticsDto>(res);
  } catch {
    return null;
  }
}

export async function pauseCampaign(
  campaignId: string,
  reason?: string,
): Promise<{ success: boolean; message?: string }> {
  try {
    const query = reason ? `?reason=${encodeURIComponent(reason)}` : "";
    const res = await fetchWithAuth(`/api/v1/security/campaigns/${campaignId}/pause${query}`, {
      method: "POST",
    });
    const body = await parseResponseBody(res);
    return {
      success: res.ok,
      message: getResponseMessage(body, res.ok ? "Campaign paused." : "Failed to pause campaign."),
    };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Failed to pause campaign.") };
  }
}

export async function resumeCampaign(campaignId: string): Promise<{ success: boolean; message?: string }> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/campaigns/${campaignId}/resume`, { method: "POST" });
    const body = await parseResponseBody(res);
    return {
      success: res.ok,
      message: getResponseMessage(body, res.ok ? "Campaign resumed." : "Failed to resume campaign."),
    };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Failed to resume campaign.") };
  }
}

export async function triggerCampaignRunNow(campaignId: string): Promise<{ success: boolean; message?: string }> {
  try {
    const res = await fetchWithAuth(`/api/v1/security/campaigns/${campaignId}/run-now`, { method: "POST" });
    const body = await parseResponseBody(res);
    return {
      success: res.ok,
      message: getResponseMessage(body, res.ok ? "Campaign run dispatched." : "Failed to trigger run-now."),
    };
  } catch (error: unknown) {
    return { success: false, message: getErrorMessage(error, "Failed to trigger run-now.") };
  }
}
