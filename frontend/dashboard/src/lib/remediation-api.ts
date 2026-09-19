import {
  ApiError,
  apiFetch,
  getResponseMessage,
  parseJsonResponse,
  parseResponseBody,
} from "@/lib/api-client";

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

export interface RemediationTransitionResponse {
  message: string;
  actionId: string;
  newVersion: number;
  status: RemediationActionStatus;
}

export interface RemediationExecutionResponse {
  message: string;
  executionId: string;
  status: string;
  success: boolean;
  failureReason?: string;
}

export interface RemediationVerificationResponse {
  message: string;
  verificationId: string;
  status: string;
  riskDelta: number;
}

export class RemediationConcurrencyError extends ApiError {
  readonly isConcurrencyConflict = true;

  constructor(message: string, response: Response, body: unknown) {
    super(message, {
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      body,
    });
    this.name = "RemediationConcurrencyError";
  }
}

export function isRemediationConcurrencyError(error: unknown): error is RemediationConcurrencyError {
  return error instanceof RemediationConcurrencyError;
}

async function parseRequiredJson<T>(response: Response, fallbackMessage: string): Promise<T> {
  if (!response.ok) throw new Error(fallbackMessage);

  const data = await parseJsonResponse<T>(response);
  if (data === null) throw new Error(fallbackMessage);
  return data;
}

async function parseMutationResponse<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = await parseResponseBody(response);

  if (response.status === 409) {
    throw new RemediationConcurrencyError(
      getResponseMessage(body, "Version conflict. Please refresh."),
      response,
      body,
    );
  }

  if (!response.ok) {
    throw ApiError.fromResponse(response, body, fallbackMessage);
  }

  return body as T;
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

  const response = await apiFetch(`/api/v1/security/remediation?${query.toString()}`);
  return parseRequiredJson<RemediationListResponse>(response, "Failed to fetch remediation actions");
}

export async function fetchRemediationActionById(id: string): Promise<RemediationActionDetailDto> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}`);
  return parseRequiredJson<RemediationActionDetailDto>(response, `Failed to fetch remediation action ${id}`);
}

export async function fetchRemediationHistory(id: string): Promise<RemediationActionHistoryDto[]> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/history`);
  return parseRequiredJson<RemediationActionHistoryDto[]>(response, `Failed to fetch history for action ${id}`);
}

export async function fetchRemediationVerification(id: string): Promise<RemediationVerificationDto> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/verification`);
  return parseRequiredJson<RemediationVerificationDto>(response, `Failed to fetch verification for action ${id}`);
}

export async function approveRemediationAction(
  id: string,
  expectedVersion: number,
  reason: string,
): Promise<RemediationTransitionResponse> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion, reason }),
  });
  return parseMutationResponse<RemediationTransitionResponse>(response, "Failed to approve action");
}

export async function rejectRemediationAction(
  id: string,
  expectedVersion: number,
  reason: string,
): Promise<RemediationTransitionResponse> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion, reason }),
  });
  return parseMutationResponse<RemediationTransitionResponse>(response, "Failed to reject action");
}

export async function executeRemediationAction(
  id: string,
  expectedVersion: number,
): Promise<RemediationExecutionResponse> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion }),
  });
  return parseMutationResponse<RemediationExecutionResponse>(response, "Failed to execute action");
}

export async function verifyRemediationAction(
  id: string,
  expectedVersion: number,
  verificationReason?: string,
): Promise<RemediationVerificationResponse> {
  const response = await apiFetch(`/api/v1/security/remediation/${id}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expectedVersion, verificationReason }),
  });
  return parseMutationResponse<RemediationVerificationResponse>(response, "Failed to verify action");
}
