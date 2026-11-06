using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/validation")]
public class CredentialValidationController : ControllerBase
{
    private readonly CredentialValidationService _validationService;
    private readonly IPlatformDbContext _dbContext;
    private readonly ICurrentUserContext _currentUser;
    private readonly PermissionService _permissionService;

    public CredentialValidationController(
        CredentialValidationService validationService,
        IPlatformDbContext dbContext,
        ICurrentUserContext currentUser,
        PermissionService permissionService)
    {
        _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        _permissionService = permissionService ?? throw new ArgumentNullException(nameof(permissionService));
    }

    [HttpPost("candidates/{candidateId:guid}/validate")]
    public async Task<IActionResult> ValidateCandidate(Guid candidateId, [FromQuery] bool immediate = true, CancellationToken ct = default)
    {
        if (await EnsureJobManagerAsync(ct) is { } denied) return denied;

        if (immediate)
        {
            var result = await _validationService.ValidateCandidateAsync(candidateId, null, ct);
            return Ok(result);
        }
        else
        {
            var job = await _validationService.EnqueueValidationJobAsync(candidateId, ct);
            return Accepted(new { jobId = job.Id, status = job.Status.ToString() });
        }
    }

    [HttpGet("candidates/{candidateId:guid}/history")]
    public async Task<IActionResult> GetValidationHistory(Guid candidateId, CancellationToken ct = default)
    {
        var history = await _validationService.GetValidationHistoryAsync(candidateId, ct);
        return Ok(history);
    }

    [HttpGet("results/{resultId:guid}")]
    public async Task<IActionResult> GetValidationResult(Guid resultId, CancellationToken ct = default)
    {
        var result = await _dbContext.CredentialValidationResults
            .Include(r => r.Candidate)
            .FirstOrDefaultAsync(r => r.Id == resultId, ct);

        if (result == null) return NotFound();
        return Ok(result);
    }

    [HttpGet("pending-approvals")]
    public async Task<IActionResult> GetPendingApprovals(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        if (await EnsureJobManagerAsync(ct) is { } denied) return denied;

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);

        var query = _dbContext.AnalysisJobs
            .Where(j => j.JobType == JobType.CredentialValidation && j.Status == JobStatus.Paused);

        var total = await query.CountAsync(ct);
        var jobs = await query
            .OrderBy(j => j.QueuedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        var items = jobs.Select(j =>
        {
            var payload = ParsePayload(j.PayloadJson);
            return new
            {
                jobId = j.Id,
                candidateId = j.TargetEntityId,
                queuedAtUtc = j.QueuedAtUtc,
                providerName = GetString(payload, "providerName"),
                maskedValue = GetString(payload, "maskedValue"),
                filePath = GetString(payload, "filePath"),
                line = GetInt(payload, "line"),
                severity = GetString(payload, "severity"),
                investigationId = GetString(payload, "investigationId"),
                validationPlan = GetNode(payload, "validationPlan"),
                generatedCode = GetString(payload, "generatedCode")
            };
        }).ToList();

        return Ok(new { items, totalCount = total, page, pageSize });
    }

    [HttpPost("jobs/{jobId:guid}/approve")]
    public async Task<IActionResult> ApproveValidationJob(Guid jobId, CancellationToken ct = default)
    {
        if (await EnsureJobManagerAsync(ct) is { } denied) return denied;

        var job = await _dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return NotFound();
        if (job.JobType != JobType.CredentialValidation)
            return BadRequest(new { error = "Job is not a credential validation job." });
        if (job.Status != JobStatus.Paused)
            return Conflict(new { error = $"Job must be Paused to approve (current: {job.Status})." });

        var payload = ParsePayload(job.PayloadJson);
        if (payload is null)
            return BadRequest(new { error = "Job payload is invalid." });

        payload["approved"] = true;
        payload["approvedByUserId"] = _currentUser.UserId is { } approverId
            ? JsonValue.Create(approverId)
            : null;
        payload["approvedAtUtc"] = JsonValue.Create(DateTime.UtcNow);

        job.PayloadJson = payload.ToJsonString();
        job.Status = JobStatus.Queued;
        job.QueuedAtUtc = DateTime.UtcNow;
        job.StartedAtUtc = null;
        job.CompletedAtUtc = null;
        job.WorkerInstanceId = null;
        job.ErrorMessage = null;
        job.NextRetryAtUtc = null;

        AddAudit(AuditEventCode.JobResumed, job, new
        {
            action = "credential_validation_approved",
            approvedByUserId = _currentUser.UserId,
            providerName = GetString(payload, "providerName"),
            candidateId = job.TargetEntityId
        });

        await _dbContext.SaveChangesAsync(ct);

        return Ok(new { jobId = job.Id, status = job.Status.ToString() });
    }

    [HttpPost("jobs/{jobId:guid}/reject")]
    public async Task<IActionResult> RejectValidationJob(
        Guid jobId,
        [FromBody] RejectValidationJobRequest? request = null,
        CancellationToken ct = default)
    {
        if (await EnsureJobManagerAsync(ct) is { } denied) return denied;

        var job = await _dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return NotFound();
        if (job.JobType != JobType.CredentialValidation)
            return BadRequest(new { error = "Job is not a credential validation job." });
        if (job.Status != JobStatus.Paused)
            return Conflict(new { error = $"Job must be Paused to reject (current: {job.Status})." });

        var reason = string.IsNullOrWhiteSpace(request?.Reason)
            ? "Rejected by administrator."
            : request!.Reason!.Trim();

        var payload = ParsePayload(job.PayloadJson);
        if (payload is not null)
        {
            payload["rejected"] = true;
            payload["rejectionReason"] = reason;
            payload["rejectedByUserId"] = _currentUser.UserId is { } rejecterId
                ? JsonValue.Create(rejecterId)
                : null;
            payload["rejectedAtUtc"] = JsonValue.Create(DateTime.UtcNow);
            job.PayloadJson = payload.ToJsonString();
        }

        job.Status = JobStatus.Cancelled;
        job.CompletedAtUtc = DateTime.UtcNow;
        job.ErrorMessage = reason;

        AddAudit(AuditEventCode.JobCancelled, job, new
        {
            action = "credential_validation_rejected",
            rejectedByUserId = _currentUser.UserId,
            reason,
            candidateId = job.TargetEntityId
        });

        await _dbContext.SaveChangesAsync(ct);

        return Ok(new { jobId = job.Id, status = job.Status.ToString() });
    }

    private async Task<IActionResult?> EnsureJobManagerAsync(CancellationToken ct)
    {
        if (_currentUser.IsPlatformAdmin) return null;

        var hasPermission = _currentUser.UserId.HasValue &&
            await _permissionService.HasPermissionAsync(_currentUser.UserId.Value, "job.manage", ct);

        return hasPermission ? null : Forbid();
    }

    private void AddAudit(AuditEventCode eventCode, AnalysisJob job, object metadata)
    {
        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = eventCode,
            UserId = _currentUser.UserId,
            ResourceType = "AnalysisJob",
            ResourceId = job.Id.ToString(),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString(),
            Metadata = JsonSerializer.Serialize(metadata)
        });
    }

    private static JsonObject? ParsePayload(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            return JsonNode.Parse(json) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? GetString(JsonObject? payload, string name) =>
        payload?[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static int? GetInt(JsonObject? payload, string name) =>
        payload?[name] is JsonValue value && value.TryGetValue<int>(out var number) ? number : null;

    private static bool GetBool(JsonObject? payload, string name) =>
        payload?[name] is JsonValue value && value.TryGetValue<bool>(out var flag) && flag;

    private static JsonNode? GetNode(JsonObject? payload, string name) => payload?[name]?.DeepClone();
}

public sealed record RejectValidationJobRequest(string? Reason);
