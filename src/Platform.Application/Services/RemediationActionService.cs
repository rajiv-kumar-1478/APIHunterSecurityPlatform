using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Application.Services;

public record CreateRemediationActionRequest(
    Guid FindingId,
    RemediationActionType ActionType,
    string Title,
    string Description,
    string? ProviderKey = null,
    string? ProviderResourceReference = null,
    int ExpiryHours = 24,
    string? Reason = null);

public record TransitionRemediationActionStatusRequest(
    Guid ActionId,
    RemediationActionStatus NewStatus,
    int ExpectedVersion,
    string Reason);

public class RemediationActionService(
    IPlatformDbContext dbContext,
    IAuditService auditService,
    ICurrentUserContext currentUserContext,
    RemediationRecommendationEngine recommendationEngine,
    ResponsePolicyEngine policyEngine,
    ResponsePolicyOptions policyOptions)
{
    private static readonly HashSet<RemediationActionStatus> TerminalStatuses = new()
    {
        RemediationActionStatus.Rejected,
        RemediationActionStatus.Failed,
        RemediationActionStatus.Cancelled,
        RemediationActionStatus.Verified,
        RemediationActionStatus.VerificationFailed
    };

    /// <summary>
    /// Creates or returns an active proposed remediation action for a finding.
    /// STRICT BOUNDARY: Operates on governance metadata only. No provider API execution or secret decryption.
    /// </summary>
    public async Task<RemediationAction> CreateActionAsync(CreateRemediationActionRequest request, CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Title)) throw new ArgumentException("Action title is required.", nameof(request.Title));

        var finding = await dbContext.SecurityFindings
            .FirstOrDefaultAsync(f => f.Id == request.FindingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{request.FindingId}' not found.");

        string fingerprint = FingerprintUtils.ComputeSha256(
            $"remediation:{finding.Id:N}:{request.ActionType}:{request.ProviderKey}:{request.ProviderResourceReference}");

        // Smart Deduplication: return existing active action if one exists
        var existingActive = await dbContext.RemediationActions
            .FirstOrDefaultAsync(a => a.ActionFingerprint == fingerprint && !TerminalStatuses.Contains(a.Status), ct);

        if (existingActive != null)
        {
            return existingActive;
        }

        var action = new RemediationAction
        {
            FindingId = finding.Id,
            RepositoryId = finding.RepositoryId,
            ActionType = request.ActionType,
            Status = RemediationActionStatus.Proposed,
            Title = request.Title.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            ActionFingerprint = fingerprint,
            Version = 1,
            RequiresApproval = true,
            ProposedByUserId = currentUserContext.UserId,
            ExpiresAtUtc = request.ExpiryHours != 0 ? DateTime.UtcNow.AddHours(request.ExpiryHours) : null,
            ProviderKey = request.ProviderKey?.Trim(),
            ProviderResourceReference = request.ProviderResourceReference?.Trim(),
            PreExecutionRiskScore = finding.RiskScore,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };

        dbContext.RemediationActions.Add(action);

        var history = new RemediationActionHistory
        {
            RemediationActionId = action.Id,
            FromStatus = null,
            ToStatus = RemediationActionStatus.Proposed,
            ChangedByUserId = currentUserContext.UserId,
            Reason = string.IsNullOrWhiteSpace(request.Reason) ? "Remediation action proposed." : request.Reason.Trim(),
            CreatedAtUtc = DateTime.UtcNow
        };

        dbContext.RemediationActionHistories.Add(history);
        await dbContext.SaveChangesAsync(ct);

        Guid.TryParse(currentUserContext.SessionId, out var parsedSessionId);

        await auditService.RecordAsync(
            AuditEventCode.RemediateActionProposed,
            currentUserContext.UserId,
            parsedSessionId != Guid.Empty ? parsedSessionId : null,
            currentUserContext.IpAddress,
            new { ActionId = action.Id, FindingId = finding.Id, action.ActionType, action.ActionFingerprint, request.ExpiryHours },
            ct);

        return action;
    }

    /// <summary>
    /// Evaluates finding evidence against the RemediationRecommendationEngine and ResponsePolicyEngine,
    /// persisting a proposed RemediationAction if recommended and allowed by policy.
    /// Uses active fingerprint deduplication and max proposed action limits.
    /// </summary>
    public async Task<RemediationAction?> EvaluateAndRecommendActionAsync(
        Guid findingId,
        RemediationRecommendationPolicyOptions? recOptions = null,
        ResponsePolicyOptions? respOptions = null,
        string? environment = null,
        CancellationToken ct = default)
    {
        respOptions ??= policyOptions;
        recOptions ??= new RemediationRecommendationPolicyOptions();

        var finding = await dbContext.SecurityFindings
            .Include(f => f.Repository)
            .FirstOrDefaultAsync(f => f.Id == findingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{findingId}' not found.");

        var evidences = await dbContext.SecurityFindingEvidences
            .Where(e => e.FindingId == findingId)
            .ToListAsync(ct);

        // 1. Recommendation Engine Decision
        var decision = recommendationEngine.Evaluate(finding, evidences, recOptions);
        if (!decision.ShouldRecommend)
        {
            return null;
        }

        // 2. Response Policy Engine Evaluation
        string repoEnv = environment ?? (finding.Repository?.FullName?.Contains("prod", StringComparison.OrdinalIgnoreCase) == true ? "Production" : "Development");
        var policyResult = policyEngine.Evaluate(decision, finding, respOptions, repoEnv);

        Guid.TryParse(currentUserContext.SessionId, out var sessId);

        await auditService.RecordAsync(
            AuditEventCode.RemediateActionPolicyEvaluated,
            currentUserContext.UserId,
            sessId != Guid.Empty ? sessId : null,
            currentUserContext.IpAddress,
            new
            {
                findingId = finding.Id,
                actionType = decision.ActionType.ToString(),
                isAllowed = policyResult.IsAllowed,
                policyVersion = policyResult.PolicyVersion,
                matchedRuleId = policyResult.MatchedRuleId
            },
            ct);

        if (!policyResult.IsAllowed)
        {
            await auditService.RecordAsync(
                AuditEventCode.RemediateActionPolicySuppressed,
                currentUserContext.UserId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new
                {
                    findingId = finding.Id,
                    actionType = decision.ActionType.ToString(),
                    policyVersion = policyResult.PolicyVersion,
                    denialReason = policyResult.DenialReason,
                    reasonCodes = policyResult.ReasonCodes
                },
                ct);

            return null;
        }

        // 3. Active Proposal Limit Throttling Check
        int activeProposalCount = await dbContext.RemediationActions
            .CountAsync(a => a.FindingId == findingId && !TerminalStatuses.Contains(a.Status), ct);

        if (activeProposalCount >= respOptions.MaxProposedActionsPerFinding)
        {
            await auditService.RecordAsync(
                AuditEventCode.RemediateActionPolicySuppressed,
                currentUserContext.UserId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new
                {
                    findingId = finding.Id,
                    actionType = decision.ActionType.ToString(),
                    policyVersion = respOptions.PolicyVersion,
                    denialReason = $"Active proposed actions limit ({respOptions.MaxProposedActionsPerFinding}) reached for finding.",
                    reasonCodes = new[] { "PROPOSAL_LIMIT_EXCEEDED" }
                },
                ct);

            return null;
        }

        var createRequest = new CreateRemediationActionRequest(
            FindingId: finding.Id,
            ActionType: decision.ActionType,
            Title: decision.Title,
            Description: decision.Description,
            ProviderKey: decision.ProviderKey,
            ProviderResourceReference: decision.ProviderResourceReference,
            ExpiryHours: recOptions.DefaultApprovalLeaseHours,
            Reason: decision.Reason);

        return await CreateActionAsync(createRequest, ct);
    }

    public async Task<RemediationAction?> GetActionByIdAsync(Guid actionId, CancellationToken ct = default)
    {
        return await dbContext.RemediationActions
            .Include(a => a.Histories.OrderBy(h => h.CreatedAtUtc))
            .FirstOrDefaultAsync(a => a.Id == actionId, ct);
    }

    public async Task<IReadOnlyList<RemediationAction>> GetActionsForFindingAsync(Guid findingId, CancellationToken ct = default)
    {
        return await dbContext.RemediationActions
            .Where(a => a.FindingId == findingId)
            .OrderByDescending(a => a.CreatedAtUtc)
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<RemediationActionHistory>> GetActionHistoryAsync(Guid actionId, CancellationToken ct = default)
    {
        return await dbContext.RemediationActionHistories
            .Where(h => h.RemediationActionId == actionId)
            .OrderBy(h => h.CreatedAtUtc)
            .ToListAsync(ct);
    }

    /// <summary>
    /// Executes a governance status transition for a remediation action.
    /// Enforces state machine rules, optimistic concurrency, and approval lease expiry.
    /// </summary>
    public async Task<RemediationAction> TransitionStatusAsync(TransitionRemediationActionStatusRequest request, CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Reason))
            throw new ArgumentException("Mandatory governance reason is required for status transition.", nameof(request.Reason));

        var action = await dbContext.RemediationActions
            .FirstOrDefaultAsync(a => a.Id == request.ActionId, ct)
            ?? throw new KeyNotFoundException($"RemediationAction '{request.ActionId}' not found.");

        if (action.Version != request.ExpectedVersion)
        {
            throw new DbUpdateConcurrencyException(
                $"Concurrency conflict: RemediationAction version mismatch. Expected v{request.ExpectedVersion}, but current is v{action.Version}.");
        }

        if (TerminalStatuses.Contains(action.Status))
        {
            throw new InvalidOperationException($"Cannot transition RemediationAction '{action.Id}' from terminal status '{action.Status}'.");
        }

        // Approval Lease Expiry Check
        if (action.ExpiresAtUtc.HasValue && action.ExpiresAtUtc.Value < DateTime.UtcNow &&
            (request.NewStatus == RemediationActionStatus.Approved || request.NewStatus == RemediationActionStatus.Executing))
        {
            throw new InvalidOperationException($"Approval lease for RemediationAction '{action.Id}' expired at {action.ExpiresAtUtc.Value:u}. Transition to '{request.NewStatus}' rejected.");
        }

        ValidateTransitionPath(action.Status, request.NewStatus);

        var oldStatus = action.Status;
        action.Status = request.NewStatus;
        action.Version += 1;
        action.UpdatedAtUtc = DateTime.UtcNow;

        if (request.NewStatus == RemediationActionStatus.Approved)
        {
            action.ApprovedByUserId = currentUserContext.UserId;
            action.ApprovedAtUtc = DateTime.UtcNow;
            action.ApprovalReason = request.Reason.Trim();
        }
        else if (request.NewStatus == RemediationActionStatus.Rejected)
        {
            action.RejectedByUserId = currentUserContext.UserId;
            action.RejectedAtUtc = DateTime.UtcNow;
            action.RejectionReason = request.Reason.Trim();
        }
        else if (request.NewStatus == RemediationActionStatus.Executing)
        {
            action.ExecutionStartedAtUtc = DateTime.UtcNow;
        }
        else if (request.NewStatus == RemediationActionStatus.Succeeded || request.NewStatus == RemediationActionStatus.Failed)
        {
            action.ExecutionCompletedAtUtc = DateTime.UtcNow;
        }

        var history = new RemediationActionHistory
        {
            RemediationActionId = action.Id,
            FromStatus = oldStatus,
            ToStatus = request.NewStatus,
            ChangedByUserId = currentUserContext.UserId,
            Reason = request.Reason.Trim(),
            CreatedAtUtc = DateTime.UtcNow
        };

        dbContext.RemediationActionHistories.Add(history);
        await dbContext.SaveChangesAsync(ct);

        var auditCode = request.NewStatus switch
        {
            RemediationActionStatus.Approved => AuditEventCode.RemediateActionApproved,
            RemediationActionStatus.Rejected => AuditEventCode.RemediateActionRejected,
            RemediationActionStatus.Cancelled => AuditEventCode.RemediateActionCancelled,
            _ => AuditEventCode.RemediateActionStatusChanged
        };

        Guid.TryParse(currentUserContext.SessionId, out var transitionSessionId);

        await auditService.RecordAsync(
            auditCode,
            currentUserContext.UserId,
            transitionSessionId != Guid.Empty ? transitionSessionId : null,
            currentUserContext.IpAddress,
            new { ActionId = action.Id, oldStatus, newStatus = request.NewStatus, action.Version, request.Reason },
            ct);

        return action;
    }

    private static void ValidateTransitionPath(RemediationActionStatus from, RemediationActionStatus to)
    {
        bool valid = (from, to) switch
        {
            (RemediationActionStatus.Proposed, RemediationActionStatus.PendingApproval) => true,
            (RemediationActionStatus.Proposed, RemediationActionStatus.Cancelled) => true,

            (RemediationActionStatus.PendingApproval, RemediationActionStatus.Approved) => true,
            (RemediationActionStatus.PendingApproval, RemediationActionStatus.Rejected) => true,
            (RemediationActionStatus.PendingApproval, RemediationActionStatus.Cancelled) => true,

            (RemediationActionStatus.Approved, RemediationActionStatus.Executing) => true,
            (RemediationActionStatus.Approved, RemediationActionStatus.Cancelled) => true,

            (RemediationActionStatus.Executing, RemediationActionStatus.Succeeded) => true,
            (RemediationActionStatus.Executing, RemediationActionStatus.Failed) => true,

            (RemediationActionStatus.Succeeded, RemediationActionStatus.VerificationPending) => true,

            (RemediationActionStatus.VerificationPending, RemediationActionStatus.Verified) => true,
            (RemediationActionStatus.VerificationPending, RemediationActionStatus.VerificationFailed) => true,

            _ => false
        };

        if (!valid)
        {
            throw new InvalidOperationException($"Invalid RemediationAction status transition path: '{from}' ➔ '{to}'.");
        }
    }
}
