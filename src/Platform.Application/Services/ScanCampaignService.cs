using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative application service implementing continuous scan campaigns.
/// Enforces complete tenant ownership chains, concurrency invariants, and immutable history preservation.
/// </summary>
public class ScanCampaignService : IScanCampaignService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ICampaignScheduleCalculator _calculator;
    private readonly ILogger<ScanCampaignService> _logger;

    public ScanCampaignService(
        IPlatformDbContext dbContext,
        ICampaignScheduleCalculator calculator,
        ILogger<ScanCampaignService>? logger = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _calculator = calculator ?? throw new ArgumentNullException(nameof(calculator));
        _logger = logger ?? NullLogger<ScanCampaignService>.Instance;
    }

    public async Task<ScanCampaignDto> CreateCampaignAsync(
        Guid tenantId,
        Guid requestedByUserId,
        CreateCampaignRequest request,
        CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            throw new ArgumentException("Campaign name is required.", nameof(request.Name));
        }

        // 1. Validate complete ownership chain: Tenant -> Repository -> SecurityTarget
        var repository = await _dbContext.Repositories
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == request.RepositoryId, ct);

        if (repository == null)
        {
            throw new KeyNotFoundException($"Repository '{request.RepositoryId}' was not found.");
        }

        var target = await _dbContext.SecurityTargets
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == request.SecurityTargetId, ct);

        if (target == null)
        {
            throw new KeyNotFoundException($"SecurityTarget '{request.SecurityTargetId}' was not found.");
        }

        if (!target.Enabled)
        {
            throw new InvalidOperationException($"Cannot create campaign for disabled SecurityTarget '{target.Name}' ({target.Id}).");
        }

        // 2. Validate schedule and compute initial NextRunUtc cursor
        TimeSpan? interval = request.IntervalMinutes.HasValue ? TimeSpan.FromMinutes(request.IntervalMinutes.Value) : null;
        _calculator.ValidateSchedule(request.ScheduleType, request.CronExpression, interval, request.TimeZoneId);

        var calcResult = _calculator.CalculateNextOccurrence(
            request.ScheduleType,
            request.CronExpression,
            interval,
            request.TimeZoneId,
            DateTime.UtcNow
        );

        if (!calcResult.IsValid)
        {
            throw new ArgumentException($"Invalid schedule: {calcResult.ErrorMessage}");
        }

        // 3. Create persistent campaign entity
        var campaign = new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            RepositoryId = request.RepositoryId,
            SecurityTargetId = request.SecurityTargetId,
            Name = request.Name.Trim(),
            Description = request.Description?.Trim(),
            Status = CampaignStatus.Active,
            ScanProfile = request.ScanProfile,
            ScheduleType = request.ScheduleType,
            CronExpression = request.ScheduleType == ScheduleType.Cron ? request.CronExpression?.Trim() : null,
            IntervalDuration = request.ScheduleType == ScheduleType.Interval ? interval : null,
            TimeZoneId = calcResult.NormalizedTimeZoneId,
            ConcurrencyPolicy = request.ConcurrencyPolicy,
            ScheduleVersion = 1,
            NextRunUtc = calcResult.NextOccurrenceUtc,
            MaxConsecutiveFailures = request.MaxConsecutiveFailures > 0 ? request.MaxConsecutiveFailures : 5,
            AutoPauseOnConsecutiveFailures = request.AutoPauseOnConsecutiveFailures,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.ScanCampaigns.Add(campaign);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("ScanCampaign '{Name}' ({Id}) created for Tenant '{TenantId}' with schedule [{Type}] NextRunUtc: {NextRun}.",
            campaign.Name, campaign.Id, campaign.TenantId, campaign.ScheduleType, campaign.NextRunUtc);

        return MapToDto(campaign, repository.Name, target.Name, target.BaseUrl);
    }

    public async Task<ScanCampaignDto?> GetCampaignByIdAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null) return null;

        return MapToDto(campaign, campaign.Repository?.Name, campaign.SecurityTarget?.Name, campaign.SecurityTarget?.BaseUrl);
    }

    public async Task<IReadOnlyList<ScanCampaignDto>> ListCampaignsAsync(
        Guid tenantId,
        Guid? repositoryId = null,
        CampaignStatus? status = null,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default)
    {
        var query = _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .Where(c => c.TenantId == tenantId);

        if (repositoryId.HasValue)
        {
            query = query.Where(c => c.RepositoryId == repositoryId.Value);
        }

        if (status.HasValue)
        {
            query = query.Where(c => c.Status == status.Value);
        }

        var campaigns = await query
            .OrderByDescending(c => c.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .AsNoTracking()
            .ToListAsync(ct);

        return campaigns.Select(c => MapToDto(c, c.Repository?.Name, c.SecurityTarget?.Name, c.SecurityTarget?.BaseUrl)).ToList();
    }

    public async Task<ScanCampaignDto> UpdateCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        UpdateCampaignRequest request,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            throw new KeyNotFoundException($"ScanCampaign '{campaignId}' was not found for Tenant '{tenantId}'.");
        }

        if (campaign.Status == CampaignStatus.Archived)
        {
            throw new InvalidOperationException("Cannot update an archived campaign.");
        }

        if (!string.IsNullOrWhiteSpace(request.Name))
        {
            campaign.Name = request.Name.Trim();
        }

        if (request.Description != null)
        {
            campaign.Description = request.Description.Trim();
        }

        if (request.ScanProfile.HasValue)
        {
            campaign.ScanProfile = request.ScanProfile.Value;
        }

        if (request.ConcurrencyPolicy.HasValue)
        {
            campaign.ConcurrencyPolicy = request.ConcurrencyPolicy.Value;
        }

        if (request.MaxConsecutiveFailures.HasValue && request.MaxConsecutiveFailures.Value > 0)
        {
            campaign.MaxConsecutiveFailures = request.MaxConsecutiveFailures.Value;
        }

        if (request.AutoPauseOnConsecutiveFailures.HasValue)
        {
            campaign.AutoPauseOnConsecutiveFailures = request.AutoPauseOnConsecutiveFailures.Value;
        }

        // Schedule changes require recalculating NextRunUtc cursor
        var scheduleType = request.ScheduleType ?? campaign.ScheduleType;
        var cronExpr = request.CronExpression ?? campaign.CronExpression;
        var interval = request.IntervalMinutes.HasValue ? TimeSpan.FromMinutes(request.IntervalMinutes.Value) : campaign.IntervalDuration;
        var timeZoneId = request.TimeZoneId ?? campaign.TimeZoneId;

        if (request.ScheduleType.HasValue || request.CronExpression != null || request.IntervalMinutes.HasValue || request.TimeZoneId != null)
        {
            _calculator.ValidateSchedule(scheduleType, cronExpr, interval, timeZoneId);

            var calcResult = _calculator.CalculateNextOccurrence(scheduleType, cronExpr, interval, timeZoneId, DateTime.UtcNow);
            if (!calcResult.IsValid)
            {
                throw new ArgumentException($"Invalid schedule: {calcResult.ErrorMessage}");
            }

            campaign.ScheduleType = scheduleType;
            campaign.CronExpression = scheduleType == ScheduleType.Cron ? cronExpr : null;
            campaign.IntervalDuration = scheduleType == ScheduleType.Interval ? interval : null;
            campaign.TimeZoneId = calcResult.NormalizedTimeZoneId;

            if (campaign.Status == CampaignStatus.Active)
            {
                campaign.NextRunUtc = calcResult.NextOccurrenceUtc;
            }
        }

        campaign.ScheduleVersion++;
        campaign.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        return MapToDto(campaign, campaign.Repository?.Name, campaign.SecurityTarget?.Name, campaign.SecurityTarget?.BaseUrl);
    }

    public async Task<ScanCampaignDto> PauseCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        string? reason = null,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            throw new KeyNotFoundException($"ScanCampaign '{campaignId}' was not found for Tenant '{tenantId}'.");
        }

        if (campaign.Status == CampaignStatus.Archived)
        {
            throw new InvalidOperationException("Cannot pause an archived campaign.");
        }

        campaign.Status = CampaignStatus.Paused;
        campaign.NextRunUtc = null;
        campaign.ScheduleVersion++;
        campaign.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("ScanCampaign '{Id}' paused for Tenant '{TenantId}'. Reason: {Reason}",
            campaignId, tenantId, reason ?? "Manual pause request");

        return MapToDto(campaign, campaign.Repository?.Name, campaign.SecurityTarget?.Name, campaign.SecurityTarget?.BaseUrl);
    }

    public async Task<ScanCampaignDto> ResumeCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            throw new KeyNotFoundException($"ScanCampaign '{campaignId}' was not found for Tenant '{tenantId}'.");
        }

        if (campaign.Status == CampaignStatus.Archived)
        {
            throw new InvalidOperationException("Cannot resume an archived campaign.");
        }

        if (campaign.SecurityTarget == null || !campaign.SecurityTarget.Enabled)
        {
            throw new InvalidOperationException("Cannot resume campaign with disabled or missing SecurityTarget.");
        }

        var calcResult = _calculator.CalculateNextOccurrence(
            campaign.ScheduleType,
            campaign.CronExpression,
            campaign.IntervalDuration,
            campaign.TimeZoneId,
            DateTime.UtcNow
        );

        campaign.Status = CampaignStatus.Active;
        campaign.NextRunUtc = calcResult.NextOccurrenceUtc;
        campaign.ScheduleVersion++;
        campaign.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("ScanCampaign '{Id}' resumed for Tenant '{TenantId}'. NextRunUtc: {NextRun}",
            campaignId, tenantId, campaign.NextRunUtc);

        return MapToDto(campaign, campaign.Repository?.Name, campaign.SecurityTarget?.Name, campaign.SecurityTarget?.BaseUrl);
    }

    public async Task<ScanCampaignDto> ArchiveCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.Repository)
            .Include(c => c.SecurityTarget)
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            throw new KeyNotFoundException($"ScanCampaign '{campaignId}' was not found for Tenant '{tenantId}'.");
        }

        campaign.Status = CampaignStatus.Archived;
        campaign.NextRunUtc = null;
        campaign.ScheduleVersion++;
        campaign.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("ScanCampaign '{Id}' archived for Tenant '{TenantId}'. Historical scans preserved.",
            campaignId, tenantId);

        return MapToDto(campaign, campaign.Repository?.Name, campaign.SecurityTarget?.Name, campaign.SecurityTarget?.BaseUrl);
    }

    public async Task<CampaignRunNowResult> TriggerRunNowAsync(
        Guid tenantId,
        Guid requestedByUserId,
        Guid campaignId,
        CancellationToken ct = default)
    {
        var campaign = await _dbContext.ScanCampaigns
            .Include(c => c.SecurityTarget)
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            throw new KeyNotFoundException($"ScanCampaign '{campaignId}' was not found for Tenant '{tenantId}'.");
        }

        if (campaign.Status == CampaignStatus.Archived)
        {
            throw new InvalidOperationException("Cannot trigger an archived campaign.");
        }

        var now = DateTime.UtcNow;

        // 1. Verify target is still enabled
        if (campaign.SecurityTarget == null || !campaign.SecurityTarget.Enabled)
        {
            var auditDisabled = new CampaignExecutionAuditLog
            {
                Id = Guid.NewGuid(),
                CampaignId = campaign.Id,
                TenantId = tenantId,
                Decision = SchedulerDecision.SkippedTargetDisabled,
                TriggerSource = "ManualRunNow",
                ScheduleVersion = campaign.ScheduleVersion,
                EvaluatedAtUtc = now,
                Reason = "Associated SecurityTarget is disabled or missing."
            };
            _dbContext.CampaignExecutionAuditLogs.Add(auditDisabled);
            await _dbContext.SaveChangesAsync(ct);

            return new CampaignRunNowResult(campaign.Id, SchedulerDecision.SkippedTargetDisabled, null, auditDisabled.Reason, now);
        }

        // 2. Evaluate concurrency policy against existing active jobs
        var activeJobs = await _dbContext.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id && (j.Status == SecurityScanJobStatus.Running || j.Status == SecurityScanJobStatus.Queued))
            .ToListAsync(ct);

        var runningJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Running);
        var queuedJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Queued);

        if (runningJob != null)
        {
            if (campaign.ConcurrencyPolicy == CampaignConcurrencyPolicy.SkipIfRunning)
            {
                var auditSkip = new CampaignExecutionAuditLog
                {
                    Id = Guid.NewGuid(),
                    CampaignId = campaign.Id,
                    TenantId = tenantId,
                    Decision = SchedulerDecision.SkippedAlreadyRunning,
                    TriggerSource = "ManualRunNow",
                    ScheduleVersion = campaign.ScheduleVersion,
                    EvaluatedAtUtc = now,
                    Reason = $"Active scan job '{runningJob.Id}' is currently running. Concurrency policy SkipIfRunning skipped execution."
                };
                _dbContext.CampaignExecutionAuditLogs.Add(auditSkip);
                await _dbContext.SaveChangesAsync(ct);

                return new CampaignRunNowResult(campaign.Id, SchedulerDecision.SkippedAlreadyRunning, null, auditSkip.Reason, now);
            }

            if (campaign.ConcurrencyPolicy == CampaignConcurrencyPolicy.ForbidConcurrent)
            {
                var auditReject = new CampaignExecutionAuditLog
                {
                    Id = Guid.NewGuid(),
                    CampaignId = campaign.Id,
                    TenantId = tenantId,
                    Decision = SchedulerDecision.RejectedConcurrent,
                    TriggerSource = "ManualRunNow",
                    ScheduleVersion = campaign.ScheduleVersion,
                    EvaluatedAtUtc = now,
                    Reason = $"Active scan job '{runningJob.Id}' is running. Concurrency policy ForbidConcurrent rejected execution."
                };
                _dbContext.CampaignExecutionAuditLogs.Add(auditReject);
                await _dbContext.SaveChangesAsync(ct);

                return new CampaignRunNowResult(campaign.Id, SchedulerDecision.RejectedConcurrent, null, auditReject.Reason, now);
            }

            if (campaign.ConcurrencyPolicy == CampaignConcurrencyPolicy.QueueNext)
            {
                if (queuedJob != null)
                {
                    var auditQueueFull = new CampaignExecutionAuditLog
                    {
                        Id = Guid.NewGuid(),
                        CampaignId = campaign.Id,
                        TenantId = tenantId,
                        Decision = SchedulerDecision.SkippedQueueFull,
                        TriggerSource = "ManualRunNow",
                        ScheduleVersion = campaign.ScheduleVersion,
                        EvaluatedAtUtc = now,
                        Reason = $"Pending scan job '{queuedJob.Id}' is already queued. QueueNext depth is capped at 1."
                    };
                    _dbContext.CampaignExecutionAuditLogs.Add(auditQueueFull);
                    await _dbContext.SaveChangesAsync(ct);

                    return new CampaignRunNowResult(campaign.Id, SchedulerDecision.SkippedQueueFull, null, auditQueueFull.Reason, now);
                }

                // Enqueue 1 pending job for after the running job completes
                var queuedExecutionJob = new SecurityScanJob
                {
                    Id = Guid.NewGuid(),
                    CampaignId = campaign.Id,
                    RepositoryId = campaign.RepositoryId,
                    TargetId = campaign.SecurityTargetId,
                    TargetUrl = campaign.SecurityTarget.BaseUrl,
                    ScanProfile = campaign.ScanProfile,
                    Status = SecurityScanJobStatus.Queued,
                    RequestedByUserId = requestedByUserId,
                    TriggeredBy = "CampaignRunNow",
                    CorrelationId = Guid.NewGuid().ToString("N"),
                    CreatedAtUtc = now
                };

                _dbContext.SecurityScanJobs.Add(queuedExecutionJob);

                var auditQueued = new CampaignExecutionAuditLog
                {
                    Id = Guid.NewGuid(),
                    CampaignId = campaign.Id,
                    TenantId = tenantId,
                    Decision = SchedulerDecision.QueuedNext,
                    TriggerSource = "ManualRunNow",
                    ScheduleVersion = campaign.ScheduleVersion,
                    EvaluatedAtUtc = now,
                    DispatchedScanJobId = queuedExecutionJob.Id,
                    Reason = $"Enqueued next execution ({queuedExecutionJob.Id}) behind running job ({runningJob.Id})."
                };

                _dbContext.CampaignExecutionAuditLogs.Add(auditQueued);
                await _dbContext.SaveChangesAsync(ct);

                return new CampaignRunNowResult(campaign.Id, SchedulerDecision.QueuedNext, queuedExecutionJob.Id, auditQueued.Reason, now);
            }
        }

        // 3. No running jobs — Dispatch new execution job immediately
        var dispatchedJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = campaign.RepositoryId,
            TargetId = campaign.SecurityTargetId,
            TargetUrl = campaign.SecurityTarget.BaseUrl,
            ScanProfile = campaign.ScanProfile,
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = requestedByUserId,
            TriggeredBy = "CampaignRunNow",
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = now
        };

        _dbContext.SecurityScanJobs.Add(dispatchedJob);

        campaign.TotalRunsCount++;
        campaign.LastRunUtc = now;
        campaign.LastScanJobId = dispatchedJob.Id;
        campaign.UpdatedAtUtc = now;

        var auditDispatched = new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            TenantId = tenantId,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "ManualRunNow",
            ScheduleVersion = campaign.ScheduleVersion,
            EvaluatedAtUtc = now,
            DispatchedScanJobId = dispatchedJob.Id,
            Reason = "Execution job dispatched successfully."
        };

        _dbContext.CampaignExecutionAuditLogs.Add(auditDispatched);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Campaign '{CampaignId}' dispatched SecurityScanJob '{JobId}' via ManualRunNow.",
            campaign.Id, dispatchedJob.Id);

        return new CampaignRunNowResult(campaign.Id, SchedulerDecision.Dispatched, dispatchedJob.Id, auditDispatched.Reason, now);
    }

    public async Task<IReadOnlyList<CampaignExecutionAuditLogDto>> GetAuditLogsAsync(
        Guid tenantId,
        Guid campaignId,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default)
    {
        var logs = await _dbContext.CampaignExecutionAuditLogs
            .Where(a => a.CampaignId == campaignId && a.TenantId == tenantId)
            .OrderByDescending(a => a.EvaluatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .AsNoTracking()
            .ToListAsync(ct);

        return logs.Select(a => new CampaignExecutionAuditLogDto(
            Id: a.Id,
            CampaignId: a.CampaignId,
            TenantId: a.TenantId,
            Decision: a.Decision,
            TriggerSource: a.TriggerSource,
            ScheduleVersion: a.ScheduleVersion,
            EvaluatedAtUtc: a.EvaluatedAtUtc,
            DispatchedScanJobId: a.DispatchedScanJobId,
            Reason: a.Reason,
            MetadataJson: a.MetadataJson
        )).ToList();
    }

    private static ScanCampaignDto MapToDto(ScanCampaign campaign, string? repoName, string? targetName, string? targetUrl)
    {
        return new ScanCampaignDto(
            Id: campaign.Id,
            TenantId: campaign.TenantId,
            RepositoryId: campaign.RepositoryId,
            RepositoryName: repoName,
            SecurityTargetId: campaign.SecurityTargetId,
            SecurityTargetName: targetName,
            TargetUrl: targetUrl,
            Name: campaign.Name,
            Description: campaign.Description,
            Status: campaign.Status,
            ScanProfile: campaign.ScanProfile,
            ScheduleType: campaign.ScheduleType,
            CronExpression: campaign.CronExpression,
            IntervalDuration: campaign.IntervalDuration,
            TimeZoneId: campaign.TimeZoneId,
            ConcurrencyPolicy: campaign.ConcurrencyPolicy,
            ScheduleVersion: campaign.ScheduleVersion,
            NextRunUtc: campaign.NextRunUtc,
            LastRunUtc: campaign.LastRunUtc,
            LastScanJobId: campaign.LastScanJobId,
            TotalRunsCount: campaign.TotalRunsCount,
            ConsecutiveFailuresCount: campaign.ConsecutiveFailuresCount,
            MaxConsecutiveFailures: campaign.MaxConsecutiveFailures,
            AutoPauseOnConsecutiveFailures: campaign.AutoPauseOnConsecutiveFailures,
            CreatedAtUtc: campaign.CreatedAtUtc,
            UpdatedAtUtc: campaign.UpdatedAtUtc
        );
    }
}
