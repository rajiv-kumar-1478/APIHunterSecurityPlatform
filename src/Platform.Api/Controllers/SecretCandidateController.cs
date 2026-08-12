using Microsoft.AspNetCore.Mvc;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/candidates")]
public class SecretCandidateController(
    CandidateService candidateService,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    public record UpdateCandidateStatusRequest(CandidateStatus NewStatus, string? Note);

    [HttpGet]
    public async Task<IActionResult> GetCandidates(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] CandidateStatus? status = null,
        [FromQuery] string? credentialType = null,
        CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.view", ct);
            if (!hasPermission) return Forbid();
        }

        var (items, totalCount) = await candidateService.GetCandidatesAsync(page, pageSize, status, credentialType, ct);
        return Ok(new { Items = items, TotalCount = totalCount, Page = page, PageSize = pageSize });
    }

    [HttpGet("{id:guid}/occurrences")]
    public async Task<IActionResult> GetCandidateOccurrences(Guid id, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.view", ct);
            if (!hasPermission) return Forbid();
        }

        var occurrences = await candidateService.GetOccurrencesForCandidateAsync(id, ct);
        return Ok(occurrences);
    }

    [HttpPost("{id:guid}/reveal")]
    public async Task<IActionResult> RevealRawSecret(Guid id, CancellationToken ct = default)
    {
        // Security Boundary: Require candidate.reveal permission
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.reveal", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            var rawSecret = await candidateService.RevealRawCredentialAsync(id, ct);
            return Ok(new { RawValue = rawSecret });
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { Message = $"Candidate {id} not found." });
        }
    }

    [HttpPatch("{id:guid}/status")]
    public async Task<IActionResult> UpdateCandidateStatus(Guid id, [FromBody] UpdateCandidateStatusRequest request, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.manage", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            await candidateService.UpdateCandidateStatusAsync(id, request.NewStatus, request.Note, ct);
            return Ok(new { Message = "Candidate status updated successfully." });
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { Message = $"Candidate {id} not found." });
        }
    }

    [HttpPost("purge-raw-contexts")]
    public async Task<IActionResult> PurgeRawContexts([FromQuery] int olderThanDays = 30, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.manage", ct);
            if (!hasPermission) return Forbid();
        }

        var purgedCount = await candidateService.PurgeExpiredRawContextsAsync(olderThanDays, ct);
        return Ok(new { PurgedCount = purgedCount, Message = $"Purged raw context text for {purgedCount} occurrences older than {olderThanDays} days." });
    }
}
