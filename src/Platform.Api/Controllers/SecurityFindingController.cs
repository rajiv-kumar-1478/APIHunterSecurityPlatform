using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/findings")]
public class SecurityFindingController(
    SecurityFindingService findingService,
    SecurityFindingLifecycleService lifecycleService,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    // Client supplies: desired new status, expected version for concurrency, and optional/mandatory reason
    public record UpdateStatusRequest(FindingStatus NewStatus, int ExpectedLifecycleVersion, string? Reason);

    [HttpGet]
    public async Task<IActionResult> GetFindings(
        [FromQuery] Guid? repositoryId = null,
        [FromQuery] RiskSeverity? severity = null,
        [FromQuery] FindingStatus? status = null,
        [FromQuery] FindingType? findingType = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        var (items, totalCount) = await findingService.GetFindingsAsync(repositoryId, severity, status, findingType, page, pageSize, ct);
        return Ok(new { Items = items, TotalCount = totalCount, Page = page, PageSize = pageSize });
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetFindingById(Guid id, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            var finding = await findingService.GetFindingByIdAsync(id, ct);
            return Ok(finding);
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { Message = $"SecurityFinding '{id}' not found." });
        }
    }

    [HttpGet("{id:guid}/evidence")]
    public async Task<IActionResult> GetFindingEvidences(Guid id, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        var evidences = await findingService.GetFindingEvidencesAsync(id, ct);
        return Ok(evidences);
    }

    /// <summary>
    /// Returns the append-only lifecycle status history for a finding.
    /// </summary>
    [HttpGet("{id:guid}/history")]
    public async Task<IActionResult> GetFindingStatusHistory(Guid id, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        var history = await lifecycleService.GetFindingStatusHistoryAsync(id, ct);
        return Ok(history);
    }

    /// <summary>
    /// Governance transition — requires authorized actor.
    /// ChangedByUserId is always derived from the authenticated session; never from client input.
    /// </summary>
    [HttpPatch("{id:guid}/status")]
    public async Task<IActionResult> UpdateFindingStatus(Guid id, [FromBody] UpdateStatusRequest request, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.manage", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            var finding = await lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(id, request.NewStatus, request.ExpectedLifecycleVersion, request.Reason),
                ct);

            return Ok(new
            {
                Message = "SecurityFinding status transitioned successfully.",
                Status = finding.Status,
                LifecycleVersion = finding.LifecycleVersion
            });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { Message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { Message = ex.Message });
        }
        catch (DbUpdateConcurrencyException ex)
        {
            return Conflict(new { Message = "Concurrency conflict: the finding was modified by another request. Reload and try again.", Detail = ex.Message });
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { Message = $"SecurityFinding '{id}' not found." });
        }
    }
}
