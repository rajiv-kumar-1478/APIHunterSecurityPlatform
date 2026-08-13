using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Providers;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record ExecuteRemediationActionRequest(
    Guid ActionId,
    int ExpectedVersion,
    string? ExecutionReason = null);

/// <summary>
/// Authoritative Remediation Execution Engine.
/// Connects approved RemediationAction records to safe provider adapters protected by 6 execution guards,
/// atomic execution claims before external provider calls, and post-execution verification pending states.
/// </summary>
public class RemediationExecutionService(
    IPlatformDbContext dbContext,
    IAuditService auditService,
    ICurrentUserContext currentUserContext,
    PermissionService permissionService,
    IProtectedCredentialResolver credentialResolver,
    IEnumerable<IRemediationProvider> providers)
{
    private static readonly HashSet<FindingStatus> InactiveFindingStatuses = new()
    {
        FindingStatus.Resolved,
        FindingStatus.Remediated,
        FindingStatus.FalsePositive,
        FindingStatus.AcceptedRisk
    };

    public async Task<RemediationExecution> ExecuteActionAsync(ExecuteRemediationActionRequest request, CancellationToken ct = default)
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
            throw new UnauthorizedAccessException("User is not authorized to execute remediation actions. Required permission: 'remediation.execute' or 'remediation.manage'.");
        }

        // 2. Fetch Action + Associated Finding
        var action = await dbContext.RemediationActions
            .Include(a => a.Finding)
            .FirstOrDefaultAsync(a => a.Id == request.ActionId, ct)
            ?? throw new KeyNotFoundException($"RemediationAction '{request.ActionId}' not found.");

        // Guard 2: Action Version Token Concurrency Check
        if (action.Version != request.ExpectedVersion)
        {
            throw new DbUpdateConcurrencyException(
                $"Concurrency conflict: Expected version v{request.ExpectedVersion}, but current version is v{action.Version}.");
        }

        // Guard 6: Duplicate Execution Check
        bool alreadyExecuting = await dbContext.RemediationExecutions
            .AnyAsync(e => e.RemediationActionId == action.Id && e.ActionVersion == request.ExpectedVersion, ct);

        if (alreadyExecuting)
        {
            throw new DbUpdateConcurrencyException($"RemediationAction '{action.Id}' at version v{request.ExpectedVersion} is already executing or executed.");
        }

        // Guard 1: Action Status MUST be Approved
        if (action.Status != RemediationActionStatus.Approved)
        {
            throw new InvalidOperationException($"Cannot execute RemediationAction '{action.Id}' in status '{action.Status}'. Only Approved actions may be executed.");
        }

        // Guard 3: Approval Lease Check
        if (action.ExpiresAtUtc.HasValue && action.ExpiresAtUtc.Value < DateTime.UtcNow)
        {
            throw new InvalidOperationException($"Approval lease for RemediationAction '{action.Id}' expired at {action.ExpiresAtUtc.Value:u}. Execution rejected.");
        }

        // Guard 4: Active Finding Guard
        if (action.Finding == null || InactiveFindingStatuses.Contains(action.Finding.Status))
        {
            throw new InvalidOperationException($"Associated finding '{action.FindingId}' is inactive (Status: {action.Finding?.Status}). Execution rejected.");
        }

        // Guard 5: Provider Capability Check
        var providerKey = action.ProviderKey?.ToLowerInvariant() ?? "fallback";
        var provider = providers.FirstOrDefault(p => p.ProviderKey.Equals(providerKey, StringComparison.OrdinalIgnoreCase))
            ?? providers.FirstOrDefault(p => p.ProviderKey.Equals("fallback", StringComparison.OrdinalIgnoreCase));

        if (provider == null || !provider.Supports(action.ActionType))
        {
            throw new InvalidOperationException($"No active provider adapter registered for provider key '{action.ProviderKey}' supporting action type '{action.ActionType}'. Execution rejected.");
        }

        // 3. Atomic Execution Claim BEFORE Provider API Call (Acquires execution ownership)
        action.Status = RemediationActionStatus.Executing;
        action.ExecutionStartedAtUtc = DateTime.UtcNow;
        action.Version += 1;
        action.UpdatedAtUtc = DateTime.UtcNow;

        var execution = new RemediationExecution
        {
            RemediationActionId = action.Id,
            ActionVersion = request.ExpectedVersion,
            Status = RemediationExecutionStatus.Executing,
            ProviderKey = provider.ProviderKey,
            ProviderResourceReference = action.ProviderResourceReference,
            StartedAtUtc = DateTime.UtcNow,
            PreExecutionRiskScore = action.PreExecutionRiskScore ?? action.Finding.RiskScore
        };
        dbContext.RemediationExecutions.Add(execution);

        // Commit atomic claim to DB (Throws DbUpdateConcurrencyException if another worker claimed it concurrently)
        await dbContext.SaveChangesAsync(ct);

        Guid.TryParse(currentUserContext.SessionId, out var sessId);
        await auditService.RecordAsync(
            AuditEventCode.RemediateActionExecutionStarted,
            userId,
            sessId != Guid.Empty ? sessId : null,
            currentUserContext.IpAddress,
            new { actionId = action.Id, findingId = action.FindingId, actionType = action.ActionType, executionId = execution.Id, actionVersion = execution.ActionVersion },
            ct);

        // 4. Secret Resolution & Provider Call
        ProtectedCredential? resolvedSecret = null;
        if (!string.IsNullOrWhiteSpace(action.ProviderResourceReference))
        {
            resolvedSecret = await credentialResolver.ResolveAsync(provider.ProviderKey, action.ProviderResourceReference, ct);
        }

        var execContext = new RemediationExecutionContext(
            action.Id,
            action.FindingId,
            action.RepositoryId,
            action.ActionType,
            provider.ProviderKey,
            action.ProviderResourceReference,
            action.PreExecutionRiskScore ?? action.Finding.RiskScore,
            resolvedSecret);

        RemediationProviderResult providerResult;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            providerResult = await provider.ExecuteAsync(execContext, ct);
        }
        catch (Exception ex)
        {
            providerResult = new RemediationProviderResult(
                Success: false,
                ProviderOperationId: null,
                FailureCode: "PROVIDER_EXCEPTION",
                FailureReason: $"Provider execution threw exception: {ex.Message}");
        }
        stopwatch.Stop();

        // 5. Update Execution Record & Action Lifecycle State
        execution.CompletedAtUtc = DateTime.UtcNow;
        execution.ExecutionDurationMs = stopwatch.ElapsedMilliseconds;
        execution.ProviderOperationId = providerResult.ProviderOperationId;

        if (providerResult.Success)
        {
            execution.Status = RemediationExecutionStatus.Succeeded;
            execution.Success = true;

            action.Status = RemediationActionStatus.VerificationPending; // Transition to VerificationPending for Step 6
            action.ExecutionCompletedAtUtc = DateTime.UtcNow;
            action.UpdatedAtUtc = DateTime.UtcNow;

            var history = new RemediationActionHistory
            {
                RemediationActionId = action.Id,
                FromStatus = RemediationActionStatus.Executing,
                ToStatus = RemediationActionStatus.VerificationPending,
                ChangedByUserId = userId,
                Reason = string.IsNullOrWhiteSpace(request.ExecutionReason) ? "Provider execution succeeded. Verification pending." : request.ExecutionReason,
                CreatedAtUtc = DateTime.UtcNow
            };
            dbContext.RemediationActionHistories.Add(history);

            await dbContext.SaveChangesAsync(ct);

            await auditService.RecordAsync(
                AuditEventCode.RemediateActionExecutionCompleted,
                userId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new { actionId = action.Id, findingId = action.FindingId, executionId = execution.Id, execution.ProviderOperationId, durationMs = stopwatch.ElapsedMilliseconds },
                ct);
        }
        else
        {
            execution.Status = RemediationExecutionStatus.Failed;
            execution.Success = false;
            execution.FailureCode = providerResult.FailureCode ?? "EXECUTION_FAILED";
            execution.FailureReason = providerResult.FailureReason ?? "Provider execution returned failure.";

            action.Status = RemediationActionStatus.Failed;
            action.ExecutionCompletedAtUtc = DateTime.UtcNow;
            action.UpdatedAtUtc = DateTime.UtcNow;

            var history = new RemediationActionHistory
            {
                RemediationActionId = action.Id,
                FromStatus = RemediationActionStatus.Executing,
                ToStatus = RemediationActionStatus.Failed,
                ChangedByUserId = userId,
                Reason = execution.FailureReason,
                CreatedAtUtc = DateTime.UtcNow
            };
            dbContext.RemediationActionHistories.Add(history);

            await dbContext.SaveChangesAsync(ct);

            await auditService.RecordAsync(
                AuditEventCode.RemediateActionExecutionFailed,
                userId,
                sessId != Guid.Empty ? sessId : null,
                currentUserContext.IpAddress,
                new { actionId = action.Id, findingId = action.FindingId, executionId = execution.Id, failureCode = execution.FailureCode, failureReason = execution.FailureReason },
                ct);
        }

        return execution;
    }

    public async Task<RemediationExecution?> GetExecutionByIdAsync(Guid executionId, CancellationToken ct = default)
    {
        return await dbContext.RemediationExecutions
            .Include(e => e.RemediationAction)
            .FirstOrDefaultAsync(e => e.Id == executionId, ct);
    }

    public async Task<IReadOnlyList<RemediationExecution>> GetExecutionsForActionAsync(Guid actionId, CancellationToken ct = default)
    {
        return await dbContext.RemediationExecutions
            .Where(e => e.RemediationActionId == actionId)
            .OrderByDescending(e => e.StartedAtUtc)
            .ToListAsync(ct);
    }
}
