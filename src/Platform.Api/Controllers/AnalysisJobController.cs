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
        var items = await query
            .OrderByDescending(j => j.QueuedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(j => new
            {
                j.Id,
                JobType = j.JobType.ToString(),
                j.TargetEntityType,
                j.TargetEntityId,
                j.Priority,
                Status = j.Status.ToString(),
                j.RetryCount,
                j.MaxRetries,
                j.WorkerInstanceId,
                j.ErrorMessage,
                j.QueuedAtUtc,
                j.StartedAtUtc,
                j.CompletedAtUtc,
                j.LastHeartbeatAtUtc
            })
            .ToListAsync(ct);

        return Ok(new { Items = items, TotalCount = total, Page = page, PageSize = pageSize });
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
