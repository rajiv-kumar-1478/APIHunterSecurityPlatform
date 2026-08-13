using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Auth;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

public record RemediationSummaryDto(
    int TotalActions,
    int ProposedCount,
    int PendingApprovalCount,
    int ApprovedCount,
    int ExecutingCount,
    int VerificationPendingCount,
    int VerifiedCount,
    int VerificationFailedCount,
    int FailedOrRejectedCount,
    int AttentionRequiredCount);

public record RemediationActionListDto(
    Guid Id,
    Guid FindingId,
    Guid RepositoryId,
    string RepositoryFullName,
    RemediationActionType ActionType,
    RemediationActionStatus Status,
    string Title,
    string Description,
    int Version,
    bool RequiresApproval,
    string? ProviderKey,
    string? ProviderResourceReference,
    int? PreExecutionRiskScore,
    DateTime? ExpiresAtUtc,
    Guid? ProposedByUserId,
    string? ProposedByUserName,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record RemediationActionDetailDto(
    Guid Id,
    Guid FindingId,
    string FindingTitle,
    FindingType FindingType,
    RiskSeverity FindingSeverity,
    Guid RepositoryId,
    string RepositoryFullName,
    RemediationActionType ActionType,
    RemediationActionStatus Status,
    string Title,
    string Description,
    string ActionFingerprint,
    int Version,
    bool RequiresApproval,
    string? RejectionReason,
    DateTime? ExpiresAtUtc,
    DateTime? ExecutionStartedAtUtc,
    DateTime? ExecutionCompletedAtUtc,
    string? ProviderKey,
    string? ProviderResourceReference,
    int? PreExecutionRiskScore,
    Guid? ProposedByUserId,
    string? ProposedByUserName,
    Guid? ApprovedByUserId,
    string? ApprovedByUserName,
    Guid? RejectedByUserId,
    string? RejectedByUserName,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc,
    RemediationVerificationDto? Verification);

public record RemediationActionHistoryDto(
    Guid Id,
    Guid RemediationActionId,
    RemediationActionStatus? FromStatus,
    RemediationActionStatus ToStatus,
    Guid? ChangedByUserId,
    string? ChangedByUserName,
    string? Reason,
    DateTime CreatedAtUtc);

public record RemediationVerificationDto(
    Guid Id,
    Guid RemediationActionId,
    Guid? RemediationExecutionId,
    RemediationVerificationStatus Status,
    DateTime VerifiedAtUtc,
    int PreExecutionRiskScore,
    int PostExecutionRiskScore,
    int RiskDelta,
    string? ValidationResultStatus,
    string VerificationDetailsJson,
    DateTime CreatedAtUtc);

public record ApproveRemediationRequest(
    int ExpectedVersion,
    string Reason);

public record RejectRemediationRequest(
    int ExpectedVersion,
    string Reason);

public record ExecuteRemediationRequest(
    int ExpectedVersion);

public record VerifyRemediationRequest(
    int ExpectedVersion,
    string? VerificationReason = null);

public record RemediationListResponse(
    List<RemediationActionListDto> Actions,
    RemediationSummaryDto Summary,
    int TotalCount,
    int Page,
    int PageSize);

[ApiController]
[Route("api/v1/security/remediation")]
[Authorize]
public class RemediationController(
    IPlatformDbContext dbContext,
    ICurrentUserContext currentUser,
    PermissionService permissionService,
    RemediationApprovalService approvalService,
    RemediationExecutionService executionService,
    PostRemediationVerificationService verificationService) : ControllerBase
{
    private async Task<bool> CheckViewPermissionAsync(CancellationToken ct)
    {
        if (currentUser.IsPlatformAdmin) return true;
        if (!currentUser.UserId.HasValue) return false;
        return await permissionService.HasPermissionAsync(currentUser.UserId.Value, "remediation.view", ct)
            || await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
    }

    /// <summary>
    /// Returns filterable list of remediation actions and summary statistics.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetActions(
        [FromQuery] RemediationActionStatus? status,
        [FromQuery] RemediationActionType? actionType,
        [FromQuery] string? provider,
        [FromQuery] Guid? repositoryId,
        [FromQuery] string? search,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
    {
        if (!await CheckViewPermissionAsync(ct)) return Forbid();

        var query = dbContext.RemediationActions
            .Include(a => a.Repository)
            .Include(a => a.ProposedByUser)
            .AsNoTracking();

        if (status.HasValue) query = query.Where(a => a.Status == status.Value);
        if (actionType.HasValue) query = query.Where(a => a.ActionType == actionType.Value);
        if (!string.IsNullOrWhiteSpace(provider)) query = query.Where(a => a.ProviderKey == provider);
        if (repositoryId.HasValue) query = query.Where(a => a.RepositoryId == repositoryId.Value);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchLower = search.Trim().ToLower();
            query = query.Where(a => a.Title.ToLower().Contains(searchLower) ||
                                     a.Description.ToLower().Contains(searchLower) ||
                                     a.Repository.FullName.ToLower().Contains(searchLower));
        }

        int totalCount = await query.CountAsync(ct);

        var actions = await query
            .OrderByDescending(a => a.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new RemediationActionListDto(
                a.Id,
                a.FindingId,
                a.RepositoryId,
                a.Repository.FullName,
                a.ActionType,
                a.Status,
                a.Title,
                a.Description,
                a.Version,
                a.RequiresApproval,
                a.ProviderKey,
                a.ProviderResourceReference,
                a.PreExecutionRiskScore,
                a.ExpiresAtUtc,
                a.ProposedByUserId,
                a.ProposedByUser != null ? a.ProposedByUser.Username : null,
                a.CreatedAtUtc,
                a.UpdatedAtUtc))
            .ToListAsync(ct);

        // Compute summary metrics across all actions
        var allActions = await dbContext.RemediationActions.AsNoTracking().ToListAsync(ct);
        var summary = new RemediationSummaryDto(
            TotalActions: allActions.Count,
            ProposedCount: allActions.Count(a => a.Status == RemediationActionStatus.Proposed),
            PendingApprovalCount: allActions.Count(a => a.Status == RemediationActionStatus.PendingApproval),
            ApprovedCount: allActions.Count(a => a.Status == RemediationActionStatus.Approved),
            ExecutingCount: allActions.Count(a => a.Status == RemediationActionStatus.Executing),
            VerificationPendingCount: allActions.Count(a => a.Status == RemediationActionStatus.VerificationPending),
            VerifiedCount: allActions.Count(a => a.Status == RemediationActionStatus.Verified),
            VerificationFailedCount: allActions.Count(a => a.Status == RemediationActionStatus.VerificationFailed),
            FailedOrRejectedCount: allActions.Count(a => a.Status == RemediationActionStatus.Failed || a.Status == RemediationActionStatus.Rejected),
            AttentionRequiredCount: allActions.Count(a => a.Status == RemediationActionStatus.Proposed ||
                                                         a.Status == RemediationActionStatus.PendingApproval ||
                                                         a.Status == RemediationActionStatus.VerificationFailed));

        return Ok(new RemediationListResponse(actions, summary, totalCount, page, pageSize));
    }

    /// <summary>
    /// Returns detailed view of a single remediation action.
    /// </summary>
    [HttpGet("{actionId:guid}")]
    public async Task<IActionResult> GetActionById(Guid actionId, CancellationToken ct = default)
    {
        if (!await CheckViewPermissionAsync(ct)) return Forbid();

        var action = await dbContext.RemediationActions
            .Include(a => a.Finding)
            .Include(a => a.Repository)
            .Include(a => a.ProposedByUser)
            .Include(a => a.ApprovedByUser)
            .Include(a => a.RejectedByUser)
            .Include(a => a.Verification)
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.Id == actionId, ct);

        if (action == null) return NotFound(new { message = $"Remediation action '{actionId}' not found." });

        RemediationVerificationDto? verifDto = action.Verification != null
            ? new RemediationVerificationDto(
                action.Verification.Id,
                action.Verification.RemediationActionId,
                action.Verification.RemediationExecutionId,
                action.Verification.Status,
                action.Verification.VerifiedAtUtc,
                action.Verification.PreExecutionRiskScore,
                action.Verification.PostExecutionRiskScore,
                action.Verification.RiskDelta,
                action.Verification.ValidationResultStatus,
                action.Verification.VerificationDetailsJson,
                action.Verification.CreatedAtUtc)
            : null;

        var detailDto = new RemediationActionDetailDto(
            action.Id,
            action.FindingId,
            action.Finding.Title,
            action.Finding.FindingType,
            action.Finding.Severity,
            action.RepositoryId,
            action.Repository.FullName,
            action.ActionType,
            action.Status,
            action.Title,
            action.Description,
            action.ActionFingerprint,
            action.Version,
            action.RequiresApproval,
            action.RejectionReason,
            action.ExpiresAtUtc,
            action.ExecutionStartedAtUtc,
            action.ExecutionCompletedAtUtc,
            action.ProviderKey,
            action.ProviderResourceReference,
            action.PreExecutionRiskScore,
            action.ProposedByUserId,
            action.ProposedByUser?.Username,
            action.ApprovedByUserId,
            action.ApprovedByUser?.Username,
            action.RejectedByUserId,
            action.RejectedByUser?.Username,
            action.CreatedAtUtc,
            action.UpdatedAtUtc,
            verifDto);

        return Ok(detailDto);
    }

    /// <summary>
    /// Returns immutable action history timeline.
    /// </summary>
    [HttpGet("{actionId:guid}/history")]
    public async Task<IActionResult> GetActionHistory(Guid actionId, CancellationToken ct = default)
    {
        if (!await CheckViewPermissionAsync(ct)) return Forbid();

        var history = await dbContext.RemediationActionHistories
            .Include(h => h.ChangedByUser)
            .Where(h => h.RemediationActionId == actionId)
            .OrderByDescending(h => h.CreatedAtUtc)
            .AsNoTracking()
            .Select(h => new RemediationActionHistoryDto(
                h.Id,
                h.RemediationActionId,
                h.FromStatus,
                h.ToStatus,
                h.ChangedByUserId,
                h.ChangedByUser != null ? h.ChangedByUser.Username : null,
                h.Reason,
                h.CreatedAtUtc))
            .ToListAsync(ct);

        return Ok(history);
    }

    /// <summary>
    /// Returns verification outcome details for an action.
    /// </summary>
    [HttpGet("{actionId:guid}/verification")]
    public async Task<IActionResult> GetActionVerification(Guid actionId, CancellationToken ct = default)
    {
        if (!await CheckViewPermissionAsync(ct)) return Forbid();

        var verification = await verificationService.GetVerificationForActionAsync(actionId, ct);
        if (verification == null) return NotFound(new { message = $"Verification record for action '{actionId}' not found." });

        var dto = new RemediationVerificationDto(
            verification.Id,
            verification.RemediationActionId,
            verification.RemediationExecutionId,
            verification.Status,
            verification.VerifiedAtUtc,
            verification.PreExecutionRiskScore,
            verification.PostExecutionRiskScore,
            verification.RiskDelta,
            verification.ValidationResultStatus,
            verification.VerificationDetailsJson,
            verification.CreatedAtUtc);

        return Ok(dto);
    }

    /// <summary>
    /// Approves a proposed/pending remediation action.
    /// </summary>
    [HttpPost("{actionId:guid}/approve")]
    public async Task<IActionResult> ApproveAction(Guid actionId, [FromBody] ApproveRemediationRequest req, CancellationToken ct = default)
    {
        if (req == null) return BadRequest(new { message = "Invalid request payload." });

        try
        {
            var action = await approvalService.ApproveActionAsync(new ApproveRemediationActionRequest(actionId, req.ExpectedVersion, req.Reason), ct);
            return Ok(new { message = "Remediation action approved successfully.", actionId = action.Id, newVersion = action.Version, status = action.Status.ToString() });
        }
        catch (UnauthorizedAccessException)
        {
            return Forbid();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            return Conflict(new { message = ex.Message, code = "CONCURRENCY_CONFLICT", actionId });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Rejects a proposed/pending remediation action.
    /// </summary>
    [HttpPost("{actionId:guid}/reject")]
    public async Task<IActionResult> RejectAction(Guid actionId, [FromBody] RejectRemediationRequest req, CancellationToken ct = default)
    {
        if (req == null) return BadRequest(new { message = "Invalid request payload." });

        try
        {
            var action = await approvalService.RejectActionAsync(new RejectRemediationActionRequest(actionId, req.ExpectedVersion, req.Reason), ct);
            return Ok(new { message = "Remediation action rejected successfully.", actionId = action.Id, newVersion = action.Version, status = action.Status.ToString() });
        }
        catch (UnauthorizedAccessException)
        {
            return Forbid();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            return Conflict(new { message = ex.Message, code = "CONCURRENCY_CONFLICT", actionId });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Executes an approved remediation action safely via provider adapter.
    /// </summary>
    [HttpPost("{actionId:guid}/execute")]
    public async Task<IActionResult> ExecuteAction(Guid actionId, [FromBody] ExecuteRemediationRequest req, CancellationToken ct = default)
    {
        if (req == null) return BadRequest(new { message = "Invalid request payload." });

        try
        {
            var execution = await executionService.ExecuteActionAsync(new ExecuteRemediationActionRequest(actionId, req.ExpectedVersion), ct);
            return Ok(new { message = "Remediation execution completed.", executionId = execution.Id, status = execution.Status.ToString(), success = execution.Success, failureReason = execution.FailureReason });
        }
        catch (UnauthorizedAccessException)
        {
            return Forbid();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            return Conflict(new { message = ex.Message, code = "CONCURRENCY_CONFLICT", actionId });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Verifies a post-execution remediation action.
    /// </summary>
    [HttpPost("{actionId:guid}/verify")]
    public async Task<IActionResult> VerifyAction(Guid actionId, [FromBody] VerifyRemediationRequest req, CancellationToken ct = default)
    {
        if (req == null) return BadRequest(new { message = "Invalid request payload." });

        try
        {
            var verification = await verificationService.VerifyActionAsync(new VerifyRemediationActionRequest(actionId, req.ExpectedVersion, req.VerificationReason), ct);
            return Ok(new { message = "Post-remediation verification processed.", verificationId = verification.Id, status = verification.Status.ToString(), riskDelta = verification.RiskDelta });
        }
        catch (UnauthorizedAccessException)
        {
            return Forbid();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            return Conflict(new { message = ex.Message, code = "CONCURRENCY_CONFLICT", actionId });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
    }
}
