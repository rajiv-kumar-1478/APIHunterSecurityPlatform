const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

export type RemediationActionStatus =
  | "Proposed"
  | "PendingApproval"
  | "Approved"
  | "Executing"
  | "VerificationPending"
  | "Verified"
  | "VerificationFailed"
  | "Rejected"
  | "Failed"
  | "Cancelled";

export type RemediationActionType =
  | "RevokeCredential"
  | "RotateCredential"
  | "RestrictCredentialScope"
  | "RemoveCurrentExposure"
  | "RemoveHistoricalExposure"
  | "DisableExposedService"
  | "InvestigateExposure";

export interface RemediationSummary {
  totalActions: number;
  proposedCount: number;
  pendingApprovalCount: number;
  approvedCount: number;
  executingCount: number;
  verificationPendingCount: number;
  verifiedCount: number;
  verificationFailedCount: number;
  failedOrRejectedCount: number;
  attentionRequiredCount: number;
}

export interface RemediationActionListDto {
  id: string;
  findingId: string;
  repositoryId: string;
  repositoryFullName: string;
  actionType: RemediationActionType;
  status: RemediationActionStatus;
  title: string;
  description: string;
  version: number;
  requiresApproval: boolean;
  providerKey?: string;
  providerResourceReference?: string;
  preExecutionRiskScore?: number;
  expiresAtUtc?: string;
  proposedByUserId?: string;
  proposedByUserName?: string;
  createdAtUtc: string;
  updatedAtUtc: string;
}

export interface RemediationVerificationDto {
  id: string;
  remediationActionId: string;
  remediationExecutionId?: string;
  status: "Pending" | "Verified" | "VerificationFailed";
  verifiedAtUtc: string;
  preExecutionRiskScore: number;
  postExecutionRiskScore: number;
  riskDelta: number;
  validationResultStatus?: string;
  verificationDetailsJson: string;
  createdAtUtc: string;
}

export interface RemediationActionDetailDto {
  id: string;
  findingId: string;
  findingTitle: string;
  findingType: string;
  findingSeverity: string;
  repositoryId: string;
  repositoryFullName: string;
  actionType: RemediationActionType;
  status: RemediationActionStatus;
  title: string;
  description: string;
  actionFingerprint: string;
  version: number;
  requiresApproval: boolean;
  rejectionReason?: string;
  expiresAtUtc?: string;
  executionStartedAtUtc?: string;
  executionCompletedAtUtc?: string;
  providerKey?: string;
  providerResourceReference?: string;
  preExecutionRiskScore?: number;
  proposedByUserId?: string;
  proposedByUserName?: string;
  approvedByUserId?: string;
  approvedByUserName?: string;
  rejectedByUserId?: string;
  rejectedByUserName?: string;
  createdAtUtc: string;
  updatedAtUtc: string;
  verification?: RemediationVerificationDto;
}

export interface RemediationActionHistoryDto {
  id: string;
  remediationActionId: string;
  fromStatus?: RemediationActionStatus;
  toStatus: RemediationActionStatus;
  changedByUserId?: string;
  changedByUserName?: string;
  reason?: string;
  createdAtUtc: string;
}

export interface RemediationListResponse {
  actions: RemediationActionListDto[];
  summary: RemediationSummary;
  totalCount: number;
  page: number;
  pageSize: number;
}

export interface ActionFilterParams {
  status?: string;
  actionType?: string;
  provider?: string;
  repositoryId?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

function getAuthHeader(): Record<string, string> {
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function fetchRemediationActions(params: ActionFilterParams = {}): Promise<RemediationListResponse> {
  const query = new URLSearchParams();
  if (params.status) query.append("status", params.status);
  if (params.actionType) query.append("actionType", params.actionType);
  if (params.provider) query.append("provider", params.provider);
  if (params.repositoryId) query.append("repositoryId", params.repositoryId);
  if (params.search) query.append("search", params.search);
  if (params.page) query.append("page", params.page.toString());
  if (params.pageSize) query.append("pageSize", params.pageSize.toString());

  const res = await fetch(`${API_URL}/api/v1/security/remediation?${query.toString()}`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error("Failed to fetch remediation actions");
  return res.json();
}

export async function fetchRemediationActionById(id: string): Promise<RemediationActionDetailDto> {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error(`Failed to fetch remediation action ${id}`);
  return res.json();
}

export async function fetchRemediationHistory(id: string): Promise<RemediationActionHistoryDto[]> {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/history`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error(`Failed to fetch history for action ${id}`);
  return res.json();
}

export async function fetchRemediationVerification(id: string): Promise<RemediationVerificationDto> {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/verification`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error(`Failed to fetch verification for action ${id}`);
  return res.json();
}

export async function approveRemediationAction(id: string, expectedVersion: number, reason: string) {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAuthHeader() },
    body: JSON.stringify({ expectedVersion, reason }),
  });
  const data = await res.json();
  if (res.status === 409) {
    throw { isConcurrencyConflict: true, message: data.message || "Version conflict. Please refresh." };
  }
  if (!res.ok) throw new Error(data.message || "Failed to approve action");
  return data;
}

export async function rejectRemediationAction(id: string, expectedVersion: number, reason: string) {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAuthHeader() },
    body: JSON.stringify({ expectedVersion, reason }),
  });
  const data = await res.json();
  if (res.status === 409) {
    throw { isConcurrencyConflict: true, message: data.message || "Version conflict. Please refresh." };
  }
  if (!res.ok) throw new Error(data.message || "Failed to reject action");
  return data;
}

export async function executeRemediationAction(id: string, expectedVersion: number) {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAuthHeader() },
    body: JSON.stringify({ expectedVersion }),
  });
  const data = await res.json();
  if (res.status === 409) {
    throw { isConcurrencyConflict: true, message: data.message || "Version conflict. Please refresh." };
  }
  if (!res.ok) throw new Error(data.message || "Failed to execute action");
  return data;
}

export async function verifyRemediationAction(id: string, expectedVersion: number, verificationReason?: string) {
  const res = await fetch(`${API_URL}/api/v1/security/remediation/${id}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAuthHeader() },
    body: JSON.stringify({ expectedVersion, verificationReason }),
  });
  const data = await res.json();
  if (res.status === 409) {
    throw { isConcurrencyConflict: true, message: data.message || "Version conflict. Please refresh." };
  }
  if (!res.ok) throw new Error(data.message || "Failed to verify action");
  return data;
}
