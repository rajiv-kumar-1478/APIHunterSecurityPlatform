using Microsoft.EntityFrameworkCore;
using Platform.Application.Auth;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Verification;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record VerifyRemediationActionRequest(
    Guid ActionId,
    int ExpectedVersion,
    string? VerificationReason = null);

/// <summary>
/// Authoritative Post-Remediation Verification Engine.
/// Reuses existing Phase 5/6 validation infrastructure, recalculates risk posture through SecurityFindingService,
/// attaches verification evidence, and updates action status to Verified/VerificationFailed without altering finding lifecycle.
/// </summary>
public class PostRemediationVerificationService(
    IPlatformDbContext dbContext,
    IAuditService auditService,
    ICurrentUserContext currentUserContext,
    PermissionService permissionService,
    SecurityFindingService findingService,
    IEnumerable<IVerificationStrategy> verificationStrategies)
{
    private static readonly HashSet<FindingStatus> InactiveFindingStatuses = new()
    {
        FindingStatus.Resolved,
        FindingStatus.Remediated,
        FindingStatus.FalsePositive,
        FindingStatus.AcceptedRisk
    };

    public async Task<RemediationVerification> VerifyActionAsync(VerifyRemediationActionRequest request, CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        // 1. Authorization Guard
        var userId = currentUserContext.UserId
            ?? throw new UnauthorizedAccessException("User is unauthenticated.");

        bool isAuthorized = currentUserContext.IsPlatformAdmin ||
            await permissionService.HasPermissionAsync(userId, "remediation.execute", ct) ||
            await permissionService.HasPermissionAsync(userId, "remediation.manage", ct);

        if (!isAuthorized)
        {
            throw new UnauthorizedAccessException("User is not authorized to verify remediation actions. Required permission: 'remediation.execute' or 'remediation.manage'.");
        }

        // 2. Fetch Action + Finding + Executions
        var action = await dbContext.RemediationActions
            .Include(a => a.Finding)
            .Include(a => a.Executions)
            .FirstOrDefaultAsync(a => a.Id == request.ActionId, ct)
            ?? throw new KeyNotFoundException($"RemediationAction '{request.ActionId}' not found.");

        // Guard 2: Version Token Concurrency Check
        if (action.Version != request.ExpectedVersion)
        {
            throw new DbUpdateConcurrencyException(
                $"Concurrency conflict: Expected version v{request.ExpectedVersion}, but current version is v{action.Version}.");
        }

        // Guard 3: Atomic Verification Claim Token & Stale-Claim Recovery (User Amendment 3)
        var claimTimeout = DateTime.UtcNow.AddMinutes(-10);
        if (!string.IsNullOrWhiteSpace(action.VerificationClaimToken) && action.VerificationClaimedAtUtc > claimTimeout)
        {
            throw new DbUpdateConcurrencyException($"RemediationAction '{action.Id}' is currently being verified by another process.");
        }

        // Guard 1: Status MUST be VerificationPending
        if (action.Status != RemediationActionStatus.VerificationPending)
        {
            throw new InvalidOperationException($"Cannot verify RemediationAction '{action.Id}' in status '{action.Status}'. Only VerificationPending actions may be verified.");
        }

        // Guard 3: Must have at least 1 successful execution
        var latestExecution = action.Executions
            .Where(e => e.Status == RemediationExecutionStatus.Succeeded)
            .OrderByDescending(e => e.CompletedAtUtc)
            .FirstOrDefault();

        if (latestExecution == null)
        {
            throw new InvalidOperationException($"RemediationAction '{action.Id}' has no successful execution record. Verification rejected.");
        }

        // Guard 4: Active Finding Guard
        if (action.Finding == null || InactiveFindingStatuses.Contains(action.Finding.Status))
        {
            throw new InvalidOperationException($"Associated finding '{action.FindingId}' is inactive (Status: {action.Finding?.Status}). Verification rejected.");
        }

        // 3. Atomic Verification Claim & Stale-Claim Recovery (User Amendment 3)
        var claimToken = Guid.NewGuid().ToString("N");
        action.VerificationClaimToken = claimToken;
        action.VerificationClaimedAtUtc = DateTime.UtcNow;
        action.Version += 1;
        action.UpdatedAtUtc = DateTime.UtcNow;

        await dbContext.SaveChangesAsync(ct);

        Guid.TryParse(currentUserContext.SessionId, out var sessId);
        await auditService.RecordAsync(
            AuditEventCode.RemediateActionVerificationStarted,
            userId,
            sessId != Guid.Empty ? sessId : null,
            currentUserContext.IpAddress,
            new { actionId = action.Id, findingId = action.FindingId, actionType = action.ActionType, claimToken },
            ct);

        // 4. Query Existing Phase 5/6 Revalidation Pipeline (User Amendment 1)
        var latestValidation = await dbContext.CredentialValidationResults
            .OrderByDescending(v => v.ValidatedAtUtc)
            .FirstOrDefaultAsync(ct);

        // Select verification strategy
        var strategy = verificationStrategies.FirstOrDefault(s => s.Supports(action.ActionType))
            ?? verificationStrategies.First(s => s.Supports(RemediationActionType.RevokeCredential));

        var strategyResult = await strategy.VerifyAsync(action, latestValidation, ct);

        // 5. Risk Recalculation & Evidence Attachment via SecurityFindingService (User Amendment 2)
        int preRisk = action.PreExecutionRiskScore ?? action.Finding.RiskScore;

        var attachReq = new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.ValidationResult,
            DiscoverySource: DiscoveryType.CredentialValidation,
            SourceEntityId: action.Id.ToString(),
            SafeEvidenceJson: strategyResult.DetailsJson);

        await findingService.AttachEvidenceAsync(action.FindingId, attachReq, ct);

        var updatedFinding = await dbContext.SecurityFindings.FindAsync(action.FindingId);
        int postRisk = updatedFinding?.RiskScore ?? preRisk;
        int riskDelta = preRisk - postRisk;

        // 6. Persist RemediationVerification Entity & Update Action Lifecycle State
        action.VerificationClaimToken = null;
        action.VerificationClaimedAtUtc = null;
        action.UpdatedAtUtc = DateTime.UtcNow;

        RemediationVerification verification;

        if (strategyResult.Verified)
        {
            action.Status = RemediationActionStatus.Verified;

            verification = new RemediationVerification
            {
                RemediationActionId = action.Id,
                RemediationExecutionId = latestExecution.Id,
                Status = RemediationVerificationStatus.Verified,
                VerifiedAtUtc = DateTime.UtcNow,
                PreExecutionRiskScore = preRisk,
                PostExecutionRiskScore = postRisk,
                RiskDelta = riskDelta,
                ValidationResultStatus = strategyResult.ValidationResultStatus,
                VerificationDetailsJson = strategyResult.DetailsJson
            };
            dbContext.RemediationVerifications.Add(verification);

            var history = new RemediationActionHistory
            {
                RemediationActionId = action.Id,
                FromStatus = RemediationActionStatus.VerificationPending,
                ToStatus = RemediationActionStatus.Verified,
                ChangedByUserId = userId,
                Reason = string.IsNullOrWhiteSpace(request.VerificationReason) ? "Post-remediation verification confirmed security condition removed." : request.VerificationReason,
                CreatedAtUtc = DateTime.UtcNow
            };
            dbContext.RemediationActionHistories.Add(history);

            await dbContext.SaveChangesAsync(ct);

            await auditService.RecordAsync(
                AuditEventCode.RemediateActionVerificationCompleted,
                userId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new { actionId = action.Id, findingId = action.FindingId, verificationId = verification.Id, preRisk, postRisk, riskDelta },
                ct);
        }
        else
        {
            action.Status = RemediationActionStatus.VerificationFailed;

            verification = new RemediationVerification
            {
                RemediationActionId = action.Id,
                RemediationExecutionId = latestExecution.Id,
                Status = RemediationVerificationStatus.VerificationFailed,
                VerifiedAtUtc = DateTime.UtcNow,
                PreExecutionRiskScore = preRisk,
                PostExecutionRiskScore = postRisk,
                RiskDelta = riskDelta,
                ValidationResultStatus = strategyResult.ValidationResultStatus,
                VerificationDetailsJson = strategyResult.DetailsJson
            };
            dbContext.RemediationVerifications.Add(verification);

            var history = new RemediationActionHistory
            {
                RemediationActionId = action.Id,
                FromStatus = RemediationActionStatus.VerificationPending,
                ToStatus = RemediationActionStatus.VerificationFailed,
                ChangedByUserId = userId,
                Reason = "Post-remediation verification failed. Key or exposure remains active.",
                CreatedAtUtc = DateTime.UtcNow
            };
            dbContext.RemediationActionHistories.Add(history);

            await dbContext.SaveChangesAsync(ct);

            await auditService.RecordAsync(
                AuditEventCode.RemediateActionVerificationFailed,
                userId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new { actionId = action.Id, findingId = action.FindingId, verificationId = verification.Id, preRisk, postRisk, riskDelta },
                ct);
        }

        return verification;
    }

    public async Task<RemediationVerification?> GetVerificationByIdAsync(Guid verificationId, CancellationToken ct = default)
    {
        return await dbContext.RemediationVerifications
            .Include(v => v.RemediationAction)
            .Include(v => v.RemediationExecution)
            .FirstOrDefaultAsync(v => v.Id == verificationId, ct);
    }

    public async Task<RemediationVerification?> GetVerificationForActionAsync(Guid actionId, CancellationToken ct = default)
    {
        return await dbContext.RemediationVerifications
            .Include(v => v.RemediationAction)
            .FirstOrDefaultAsync(v => v.RemediationActionId == actionId, ct);
    }
}
