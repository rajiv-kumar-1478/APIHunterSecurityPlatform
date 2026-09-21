using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/jobs")]
public class AnalysisJobController(
    JobOrchestrationService jobOrchestrationService,
    IPlatformDbContext dbContext,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetJobs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] JobStatus? status = null,
        [FromQuery] JobType? jobType = null,
        CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "job.view", ct);
            if (!hasPermission) return Forbid();
        }

        var query = dbContext.AnalysisJobs.AsQueryable();
        if (status.HasValue) query = query.Where(j => j.Status == status.Value);
        if (jobType.HasValue) query = query.Where(j => j.JobType == jobType.Value);

        var total = await query.CountAsync(ct);
        var rawItems = await query
            .OrderByDescending(j => j.QueuedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        var repoIds = rawItems
            .Where(j => j.JobType == JobType.RepositoryAcquisition)
            .Select(j => j.TargetEntityId)
            .Distinct()
            .ToList();

        var snapshotIds = rawItems
            .Where(j => j.JobType == JobType.SnapshotAnalysis)
            .Select(j => j.TargetEntityId)
            .Distinct()
            .ToList();

        var repos = await dbContext.Repositories
            .Where(r => repoIds.Contains(r.Id))
            .ToDictionaryAsync(r => r.Id, r => r.FullName, ct);

        var snapshots = await dbContext.RepositorySnapshots
            .Where(s => snapshotIds.Contains(s.Id))
            .Include(s => s.Repository)
            .ToDictionaryAsync(s => s.Id, s => s.Repository.FullName, ct);

        var items = rawItems.Select(j => new
        {
            j.Id,
            JobType = j.JobType.ToString(),
            j.TargetEntityType,
            j.TargetEntityId,
            TargetName = j.JobType == JobType.RepositoryAcquisition && repos.TryGetValue(j.TargetEntityId, out var rName)
                ? rName
                : j.JobType == JobType.SnapshotAnalysis && snapshots.TryGetValue(j.TargetEntityId, out var sName)
                    ? sName
                    : j.TargetEntityId.ToString(),
            j.Priority,
            Status = j.Status.ToString(),
            j.RetryCount,
            j.MaxRetries,
            j.WorkerInstanceId,
            j.ErrorMessage,
            j.ResultJson,
            j.QueuedAtUtc,
            j.StartedAtUtc,
            j.CompletedAtUtc,
            j.LastHeartbeatAtUtc
        }).ToList();

        return Ok(new { Items = items, TotalCount = total, Page = page, PageSize = pageSize });
    }

    [HttpPost("{id:guid}/retry")]
    public async Task<IActionResult> RetryJob([FromRoute] Guid id, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "job.manage", ct);
            if (!hasPermission) return Forbid();
        }

        var job = await dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == id, ct);
        if (job == null) return NotFound();

        job.Status = JobStatus.Queued;
        job.RetryCount = 0;
        job.ErrorMessage = null;
        job.StartedAtUtc = null;
        job.CompletedAtUtc = null;
        job.QueuedAtUtc = DateTime.UtcNow;
        await dbContext.SaveChangesAsync(ct);

        return Ok(new { Success = true, Message = "Job re-queued successfully." });
    }

    [HttpPost("sweep-stale")]
    public async Task<IActionResult> SweepStaleJobs([FromQuery] int timeoutMinutes = 5, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "job.manage", ct);
            if (!hasPermission) return Forbid();
        }

        var count = await jobOrchestrationService.SweepStaleJobsAsync(timeoutMinutes, ct);
        return Ok(new { SweptCount = count, Message = $"Re-queued {count} stale jobs." });
    }
}
