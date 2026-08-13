using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record ApproveRemediationActionRequest(
    Guid ActionId,
    int ExpectedVersion,
    string Reason);

public record RejectRemediationActionRequest(
    Guid ActionId,
    int ExpectedVersion,
    string Reason);

/// <summary>
/// Authoritative human approval & governance service for remediation actions.
/// STRICT BOUNDARY: Authorizes specific immutable action version (ActionId + Version token). Zero provider API execution.
/// </summary>
public class RemediationApprovalService(
    IPlatformDbContext dbContext,
    IAuditService auditService,
    ICurrentUserContext currentUserContext,
    PermissionService permissionService)
{
    private static readonly HashSet<FindingStatus> InactiveFindingStatuses = new()
    {
        FindingStatus.Resolved,
        FindingStatus.Remediated,
        FindingStatus.FalsePositive,
        FindingStatus.AcceptedRisk
    };

    public async Task<RemediationAction> ApproveActionAsync(ApproveRemediationActionRequest request, CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Reason))
            throw new ArgumentException("Mandatory approval reason is required.", nameof(request.Reason));

        // 1. Authorization Guard
        var userId = currentUserContext.UserId
            ?? throw new UnauthorizedAccessException("User is unauthenticated.");

        bool isAuthorized = currentUserContext.IsPlatformAdmin ||
            await permissionService.HasPermissionAsync(userId, "remediation.approve", ct) ||
            await permissionService.HasPermissionAsync(userId, "remediation.manage", ct);

        if (!isAuthorized)
        {
            throw new UnauthorizedAccessException("User is not authorized to approve remediation actions. Required permission: 'remediation.approve' or 'remediation.manage'.");
        }

        // 2. Fetch Action + Associated Finding
        var action = await dbContext.RemediationActions
            .Include(a => a.Finding)
            .FirstOrDefaultAsync(a => a.Id == request.ActionId, ct)
            ?? throw new KeyNotFoundException($"RemediationAction '{request.ActionId}' not found.");

        // 3. Version Token Concurrency Guard
        if (action.Version != request.ExpectedVersion)
        {
            throw new DbUpdateConcurrencyException(
                $"Concurrency conflict: Expected version v{request.ExpectedVersion}, but current version is v{action.Version}.");
        }

        // 4. Finding Active State Guard
        if (action.Finding == null || InactiveFindingStatuses.Contains(action.Finding.Status))
        {
            throw new InvalidOperationException($"Associated finding '{action.FindingId}' is inactive (Status: {action.Finding?.Status}). Approval rejected.");
        }

        // 5. State Machine & Lease Expiry Guards
        if (action.Status != RemediationActionStatus.Proposed && action.Status != RemediationActionStatus.PendingApproval)
        {
            throw new InvalidOperationException($"Cannot approve RemediationAction '{action.Id}' in status '{action.Status}'. Only Proposed or PendingApproval actions can be approved.");
        }

        if (action.ExpiresAtUtc.HasValue && action.ExpiresAtUtc.Value < DateTime.UtcNow)
        {
            throw new InvalidOperationException($"Approval lease for RemediationAction '{action.Id}' expired at {action.ExpiresAtUtc.Value:u}. Approval rejected.");
        }

        var oldStatus = action.Status;
        action.Status = RemediationActionStatus.Approved;
        action.ApprovedByUserId = userId;
        action.ApprovedAtUtc = DateTime.UtcNow;
        action.ApprovalReason = request.Reason.Trim();
        action.Version += 1;
        action.UpdatedAtUtc = DateTime.UtcNow;

        var history = new RemediationActionHistory
        {
            RemediationActionId = action.Id,
            FromStatus = oldStatus,
            ToStatus = RemediationActionStatus.Approved,
            ChangedByUserId = userId,
            Reason = request.Reason.Trim(),
            CreatedAtUtc = DateTime.UtcNow
        };

        dbContext.RemediationActionHistories.Add(history);

        // 6. Commit Database Mutation (EF Core checks .IsConcurrencyToken() at DB level)
        await dbContext.SaveChangesAsync(ct);

        Guid.TryParse(currentUserContext.SessionId, out var sessId);
        await auditService.RecordAsync(
            AuditEventCode.RemediateActionApproved,
            userId,
            sessId != Guid.Empty ? sessId : null,
            currentUserContext.IpAddress,
            new { action.Id, action.FindingId, action.ActionType, action.Version, request.Reason },
            ct);

        return action;
    }

    public async Task<RemediationAction> RejectActionAsync(RejectRemediationActionRequest request, CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Reason))
            throw new ArgumentException("Mandatory rejection reason is required.", nameof(request.Reason));

        // 1. Authorization Guard
        var userId = currentUserContext.UserId
            ?? throw new UnauthorizedAccessException("User is unauthenticated.");

        bool isAuthorized = currentUserContext.IsPlatformAdmin ||
            await permissionService.HasPermissionAsync(userId, "remediation.approve", ct) ||
            await permissionService.HasPermissionAsync(userId, "remediation.manage", ct);

        if (!isAuthorized)
        {
            throw new UnauthorizedAccessException("User is not authorized to reject remediation actions. Required permission: 'remediation.approve' or 'remediation.manage'.");
        }

        // 2. Fetch Action + Associated Finding
        var action = await dbContext.RemediationActions
            .Include(a => a.Finding)
            .FirstOrDefaultAsync(a => a.Id == request.ActionId, ct)
            ?? throw new KeyNotFoundException($"RemediationAction '{request.ActionId}' not found.");

        // 3. Version Token Concurrency Guard
        if (action.Version != request.ExpectedVersion)
        {
            throw new DbUpdateConcurrencyException(
                $"Concurrency conflict: Expected version v{request.ExpectedVersion}, but current version is v{action.Version}.");
        }

        // 4. Finding Active State Guard
        if (action.Finding == null || InactiveFindingStatuses.Contains(action.Finding.Status))
        {
            throw new InvalidOperationException($"Associated finding '{action.FindingId}' is inactive (Status: {action.Finding?.Status}). Rejection rejected.");
        }

        // 5. State Machine Guard
        if (action.Status != RemediationActionStatus.Proposed && action.Status != RemediationActionStatus.PendingApproval)
        {
            throw new InvalidOperationException($"Cannot reject RemediationAction '{action.Id}' in status '{action.Status}'. Only Proposed or PendingApproval actions can be rejected.");
        }

        var oldStatus = action.Status;
        action.Status = RemediationActionStatus.Rejected;
        action.RejectedByUserId = userId;
        action.RejectedAtUtc = DateTime.UtcNow;
        action.RejectionReason = request.Reason.Trim();
        action.Version += 1;
        action.UpdatedAtUtc = DateTime.UtcNow;

        var history = new RemediationActionHistory
        {
            RemediationActionId = action.Id,
            FromStatus = oldStatus,
            ToStatus = RemediationActionStatus.Rejected,
            ChangedByUserId = userId,
            Reason = request.Reason.Trim(),
            CreatedAtUtc = DateTime.UtcNow
        };

        dbContext.RemediationActionHistories.Add(history);

        // 6. Commit Database Mutation
        await dbContext.SaveChangesAsync(ct);

        Guid.TryParse(currentUserContext.SessionId, out var sessId);
        await auditService.RecordAsync(
            AuditEventCode.RemediateActionRejected,
            userId,
            sessId != Guid.Empty ? sessId : null,
            currentUserContext.IpAddress,
            new { action.Id, action.FindingId, action.ActionType, action.Version, request.Reason },
            ct);

        return action;
    }
}
