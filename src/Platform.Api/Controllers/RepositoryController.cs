using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/repositories")]
public class RepositoryController(
    RepositoryAcquisitionService acquisitionService,
    IPlatformDbContext dbContext,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    public record AddRepositoryRequest(string Url);

    [HttpGet]
    public async Task<IActionResult> GetRepositories([FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] AcquisitionStatus? status = null, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "repository.view", ct);
            if (!hasPermission) return Forbid();
        }

        var query = dbContext.Repositories.AsQueryable();
        if (status.HasValue)
        {
            query = query.Where(r => r.AcquisitionStatus == status.Value);
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(r => r.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new
            {
                r.Id,
                r.Provider,
                r.Owner,
                r.Name,
                r.FullName,
                r.Url,
                r.Description,
                r.IsPrivate,
                r.DefaultBranch,
                Status = r.AcquisitionStatus.ToString(),
                r.LastAcquiredAtUtc,
                r.CreatedAtUtc
            })
            .ToListAsync(ct);

        return Ok(new { Items = items, TotalCount = total, Page = page, PageSize = pageSize });
    }

    [HttpPost("add")]
    public async Task<IActionResult> AddRepository([FromBody] AddRepositoryRequest request, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "repository.manage", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            var repo = await acquisitionService.AddRepositoryAsync(request.Url, currentUser.UserId, ct);
            return Ok(new { repo.Id, repo.FullName, repo.Url, Status = repo.AcquisitionStatus.ToString() });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { Message = ex.Message });
        }
    }

    [HttpPost("seed-apihunter")]
    public async Task<IActionResult> SeedFromApiHunter(CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "repository.manage", ct);
            if (!hasPermission) return Forbid();
        }

        var count = await acquisitionService.SeedRepositoriesFromApiHunterAsync(currentUser.UserId, ct);
        return Ok(new { SeededCount = count, Message = $"Seeded {count} repositories from APIHunter intelligence records." });
    }

    [HttpPost("{id:guid}/acquire")]
    public async Task<IActionResult> AcquireRepositorySnapshot(Guid id, [FromQuery] string? branch = null, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "repository.manage", ct);
            if (!hasPermission) return Forbid();
        }

        try
        {
            var snapshot = await acquisitionService.AcquireSnapshotAsync(id, branch, ct);
            return Ok(new { SnapshotId = snapshot.Id, snapshot.CommitSha, snapshot.BranchName, snapshot.FileCount, Status = snapshot.AnalysisStatus.ToString() });
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { Message = $"Repository {id} not found." });
        }
    }
}
