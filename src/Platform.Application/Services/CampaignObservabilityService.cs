using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative implementation of the operational campaign read and observability service.
///
/// INVARIANTS:
/// 1. STRICT READ-ONLY: Never claims, triggers, advances, or modifies scheduler state.
/// 2. TENANT ISOLATION: All queries strictly filter by authoritative TenantId.
/// 3. BOUNDED QUERIES: History and diagnostics use bounded time ranges and pagination over indexed columns.
/// 4. HEALTH PRECEDENCE: FailClosed > Unavailable > Degraded > NotConfigured > Healthy.
/// 5. IMMUTABLE SOURCING: Recovery history and failure diagnostics derive from CampaignExecutionAuditLog.
/// </summary>
public sealed class CampaignObservabilityService : ICampaignObservabilityService
{
    private readonly IPlatformDbContext _db;
    private readonly CampaignSchedulerOptions _options;
    private readonly ILogger<CampaignObservabilityService> _logger;

    public CampaignObservabilityService(
        IPlatformDbContext db,
        IOptions<CampaignSchedulerOptions> options,
        ILogger<CampaignObservabilityService>? logger = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<CampaignObservabilityService>.Instance;
    }

    // =========================================================================
    // 1. GetTenantHealthAsync
    // =========================================================================

    public async Task<CampaignOperationalHealthDto> GetTenantHealthAsync(Guid tenantId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;

        // Query all campaigns for this tenant
        var campaigns = await _db.ScanCampaigns
            .AsNoTracking()
            .Where(c => c.TenantId == tenantId)
            .ToListAsync(ct);

        int total = campaigns.Count;
        int active = campaigns.Count(c => c.Status == CampaignStatus.Active);
        int paused = campaigns.Count(c => c.Status == CampaignStatus.Paused);
        int autoPaused = campaigns.Count(c => c.Status == CampaignStatus.AutoPaused);

        // Overdue: Active campaign with NextRunUtc older than now - 5 minutes
        var overdueGraceCutoff = now.AddMinutes(-5);
        int overdue = campaigns.Count(c => c.Status == CampaignStatus.Active
                                        && c.NextRunUtc != null
                                        && c.NextRunUtc <= overdueGraceCutoff);

        // Check scheduler worker liveness: query latest global/tenant audit log evaluation timestamp
        var latestAuditTimestamp = await _db.CampaignExecutionAuditLogs
            .AsNoTracking()
            .OrderByDescending(a => a.EvaluatedAtUtc)
            .Select(a => (DateTime?)a.EvaluatedAtUtc)
            .FirstOrDefaultAsync(ct);

        var workerLivenessThreshold = TimeSpan.FromSeconds(Math.Max(90, _options.TickIntervalSeconds * 3));
        bool workerAlive = latestAuditTimestamp.HasValue
                        && (now - latestAuditTimestamp.Value) <= workerLivenessThreshold;

        // Calculate time-bounded metrics
        var metrics24h = await GetTenantWindowMetricsAsync(tenantId, TimeSpan.FromHours(24), ct);
        var metrics7d = await GetTenantWindowMetricsAsync(tenantId, TimeSpan.FromDays(7), ct);

        // Strict Health Precedence: FailClosed > Unavailable > Degraded > NotConfigured > Healthy
        CampaignOperationalHealthStatus status;
        string reason;

        if (total == 0)
        {
            status = CampaignOperationalHealthStatus.NotConfigured;
            reason = "No continuous scan campaigns configured for tenant.";
        }
        else if (active > 0 && !workerAlive && latestAuditTimestamp.HasValue)
        {
            status = CampaignOperationalHealthStatus.Unavailable;
            reason = $"Scheduler worker heartbeat is stale. Last tick was at {latestAuditTimestamp:O} (>{workerLivenessThreshold.TotalSeconds:N0}s ago).";
        }
        else if (autoPaused > 0)
        {
            status = CampaignOperationalHealthStatus.Degraded;
            reason = $"{autoPaused} campaign(s) are currently AutoPaused due to consecutive scan/timeout failures.";
        }
        else if (overdue > 0)
        {
            status = CampaignOperationalHealthStatus.Degraded;
            reason = $"{overdue} campaign(s) are overdue for scheduled scan execution.";
        }
        else if (metrics24h.DispatchedCount > 0 && metrics24h.SuccessRatePercentage < 50.0)
        {
            status = CampaignOperationalHealthStatus.Degraded;
            reason = $"24-hour scan success rate is degraded ({metrics24h.SuccessRatePercentage:F1}%).";
        }
        else
        {
            status = CampaignOperationalHealthStatus.Healthy;
            reason = $"Scheduler operational. {active} active campaign(s), 0 overdue, 0 auto-paused.";
        }

        return new CampaignOperationalHealthDto(
            TenantId: tenantId,
            Status: status,
            StatusReason: reason,
            TotalCampaigns: total,
            ActiveCampaigns: active,
            PausedCampaigns: paused,
            AutoPausedCampaigns: autoPaused,
            OverdueCampaignsCount: overdue,
            LastSchedulerTickUtc: latestAuditTimestamp,
            SchedulerWorkerAlive: workerAlive,
            Metrics24h: metrics24h,
            Metrics7d: metrics7d,
            EvaluatedAtUtc: now
        );
    }

    // =========================================================================
    // 2. GetCampaignExecutionHistoryAsync
    // =========================================================================

    public async Task<IReadOnlyList<CampaignExecutionHistoryEntryDto>> GetCampaignExecutionHistoryAsync(
        Guid tenantId,
        Guid campaignId,
        int page = 1,
        int pageSize = 50,
        DateTime? sinceUtc = null,
        SchedulerDecision? decision = null,
        CancellationToken ct = default)
    {
        // Enforce bounding constraints
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        // Verify campaign exists and belongs to authoritative tenant
        var campaign = await _db.ScanCampaigns
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            return Array.Empty<CampaignExecutionHistoryEntryDto>();
        }

        // Bounded audit query: default to last 30 days if sinceUtc not specified
        var effectiveSince = sinceUtc ?? DateTime.UtcNow.AddDays(-30);

        var query = _db.CampaignExecutionAuditLogs
            .AsNoTracking()
            .Where(a => a.CampaignId == campaignId
                     && a.TenantId == tenantId
                     && a.EvaluatedAtUtc >= effectiveSince);

        if (decision.HasValue)
        {
            query = query.Where(a => a.Decision == decision.Value);
        }

        var auditLogs = await query
            .OrderByDescending(a => a.EvaluatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        if (auditLogs.Count == 0)
        {
            return Array.Empty<CampaignExecutionHistoryEntryDto>();
        }

        // Correlate with SecurityScanJobs in a single batch query
        var jobIds = auditLogs
            .Where(a => a.DispatchedScanJobId.HasValue)
            .Select(a => a.DispatchedScanJobId!.Value)
            .Distinct()
            .ToList();

        var jobsMap = new Dictionary<Guid, SecurityScanJob>();
        if (jobIds.Count > 0)
        {
            var jobs = await _db.SecurityScanJobs
                .AsNoTracking()
                .Where(j => jobIds.Contains(j.Id))
                .ToListAsync(ct);

            jobsMap = jobs.ToDictionary(j => j.Id);
        }

        var results = new List<CampaignExecutionHistoryEntryDto>(auditLogs.Count);
        foreach (var log in auditLogs)
        {
            SecurityScanJob? job = null;
            if (log.DispatchedScanJobId.HasValue)
            {
                jobsMap.TryGetValue(log.DispatchedScanJobId.Value, out job);
            }

            double? durationSeconds = null;
            if (job?.StartedAtUtc.HasValue == true && job.CompletedAtUtc.HasValue)
            {
                durationSeconds = (job.CompletedAtUtc.Value - job.StartedAtUtc.Value).TotalSeconds;
            }

            results.Add(new CampaignExecutionHistoryEntryDto(
                AuditLogId: log.Id,
                CampaignId: log.CampaignId,
                CampaignName: campaign.Name,
                TenantId: log.TenantId,
                Decision: log.Decision,
                TriggerSource: log.TriggerSource,
                ScheduleVersion: log.ScheduleVersion,
                EvaluatedAtUtc: log.EvaluatedAtUtc,
                Reason: log.Reason,
                OccurrenceKey: job?.CampaignOccurrenceKey,
                ScanJobId: log.DispatchedScanJobId,
                ScanJobStatus: job?.Status,
                TargetUrl: job?.TargetUrl,
                ScanProfile: job?.ScanProfile,
                ScanStartedAtUtc: job?.StartedAtUtc,
                ScanCompletedAtUtc: job?.CompletedAtUtc,
                ScanDurationSeconds: durationSeconds,
                TotalFindingsCount: job?.TotalFindingsCount,
                ScanFailureReason: job?.FailureReason
            ));
        }

        return results;
    }

    // =========================================================================
    // 3. GetCampaignDiagnosticsAsync
    // =========================================================================

    public async Task<CampaignDiagnosticsDto?> GetCampaignDiagnosticsAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default)
    {
        var campaign = await _db.ScanCampaigns
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == campaignId && c.TenantId == tenantId, ct);

        if (campaign == null)
        {
            return null;
        }

        var now = DateTime.UtcNow;
        bool isOverdue = campaign.Status == CampaignStatus.Active
                      && campaign.NextRunUtc.HasValue
                      && campaign.NextRunUtc.Value < now;

        TimeSpan? overdueBy = isOverdue ? now - campaign.NextRunUtc!.Value : null;

        // Introspect failure events from immutable audit logs (bounded to last 20 events)
        var recentFailureAudits = await _db.CampaignExecutionAuditLogs
            .AsNoTracking()
            .Where(a => a.CampaignId == campaignId
                     && a.TenantId == tenantId
                     && (a.Decision == SchedulerDecision.RejectedConcurrent
                      || a.Decision == SchedulerDecision.SkippedTargetDisabled
                      || a.Decision == SchedulerDecision.SkippedClaimLost
                      || a.Decision == SchedulerDecision.RecoveredStuck))
            .OrderByDescending(a => a.EvaluatedAtUtc)
            .Take(20)
            .ToListAsync(ct);

        var failureStreak = recentFailureAudits.Select(a => new CampaignFailureStreakEventDto(
            ScanJobId: a.DispatchedScanJobId,
            TimestampUtc: a.EvaluatedAtUtc,
            FailureType: a.Decision.ToString(),
            Reason: a.Reason
        )).ToList();

        // Introspect stuck-job recoveries strictly from immutable audit log records
        var recoveryAudits = await _db.CampaignExecutionAuditLogs
            .AsNoTracking()
            .Where(a => a.CampaignId == campaignId
                     && a.TenantId == tenantId
                     && a.Decision == SchedulerDecision.RecoveredStuck)
            .OrderByDescending(a => a.EvaluatedAtUtc)
            .Take(20)
            .ToListAsync(ct);

        var recoveries = recoveryAudits.Select(a => new CampaignRecoveryEventDto(
            AuditLogId: a.Id,
            ScanJobId: a.DispatchedScanJobId,
            RecoveredAtUtc: a.EvaluatedAtUtc,
            TriggerSource: a.TriggerSource,
            Reason: a.Reason,
            MetadataJson: a.MetadataJson
        )).ToList();

        string? autoPauseReason = null;
        DateTime? autoPausedAt = null;
        if (campaign.Status == CampaignStatus.AutoPaused)
        {
            autoPauseReason = $"Exceeded maximum consecutive failure threshold ({campaign.ConsecutiveFailuresCount}/{campaign.MaxConsecutiveFailures}).";
            autoPausedAt = campaign.UpdatedAtUtc;
        }

        return new CampaignDiagnosticsDto(
            CampaignId: campaign.Id,
            CampaignName: campaign.Name,
            Status: campaign.Status,
            ConsecutiveFailuresCount: campaign.ConsecutiveFailuresCount,
            MaxConsecutiveFailures: campaign.MaxConsecutiveFailures,
            AutoPauseOnConsecutiveFailures: campaign.AutoPauseOnConsecutiveFailures,
            AutoPauseReason: autoPauseReason,
            AutoPausedAtUtc: autoPausedAt,
            ScheduleVersion: campaign.ScheduleVersion,
            NextRunUtc: campaign.NextRunUtc,
            LastRunUtc: campaign.LastRunUtc,
            IsOverdue: isOverdue,
            OverdueBy: overdueBy,
            RecentFailureStreak: failureStreak,
            RecentRecoveries: recoveries
        );
    }

    // =========================================================================
    // 4. GetTenantWindowMetricsAsync
    // =========================================================================

    public async Task<CampaignWindowMetricsDto> GetTenantWindowMetricsAsync(
        Guid tenantId,
        TimeSpan window,
        CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var windowStart = now - window;

        // Bounded audit evaluations for this tenant in time window
        var auditLogs = await _db.CampaignExecutionAuditLogs
            .AsNoTracking()
            .Where(a => a.TenantId == tenantId && a.EvaluatedAtUtc >= windowStart)
            .ToListAsync(ct);

        int totalEvaluations = auditLogs.Count;
        int dispatched = auditLogs.Count(a => a.Decision == SchedulerDecision.Dispatched
                                           || a.Decision == SchedulerDecision.QueuedNext);
        int skipped = auditLogs.Count(a => a.Decision == SchedulerDecision.SkippedAlreadyRunning
                                        || a.Decision == SchedulerDecision.SkippedQueueFull
                                        || a.Decision == SchedulerDecision.SkippedTargetDisabled
                                        || a.Decision == SchedulerDecision.SkippedClaimLost
                                        || a.Decision == SchedulerDecision.RejectedConcurrent);
        int recoveredStuck = auditLogs.Count(a => a.Decision == SchedulerDecision.RecoveredStuck);

        // Correlate with completed scan jobs for this tenant in window
        var dispatchedJobIds = auditLogs
            .Where(a => a.DispatchedScanJobId.HasValue)
            .Select(a => a.DispatchedScanJobId!.Value)
            .Distinct()
            .ToList();

        int completedCount = 0;
        int failedCount = 0;
        double totalDurationSeconds = 0;
        int durationsCount = 0;

        if (dispatchedJobIds.Count > 0)
        {
            var jobs = await _db.SecurityScanJobs
                .AsNoTracking()
                .Where(j => dispatchedJobIds.Contains(j.Id))
                .ToListAsync(ct);

            foreach (var job in jobs)
            {
                if (job.Status == SecurityScanJobStatus.Completed || job.Status == SecurityScanJobStatus.CompletedWithWarnings)
                {
                    completedCount++;
                    if (job.StartedAtUtc.HasValue && job.CompletedAtUtc.HasValue)
                    {
                        totalDurationSeconds += (job.CompletedAtUtc.Value - job.StartedAtUtc.Value).TotalSeconds;
                        durationsCount++;
                    }
                }
                else if (job.Status == SecurityScanJobStatus.Failed || job.Status == SecurityScanJobStatus.TimedOut)
                {
                    failedCount++;
                }
            }
        }

        int finishedScans = completedCount + failedCount;
        double successRate = finishedScans > 0 ? (completedCount * 100.0) / finishedScans : 100.0;
        double avgDuration = durationsCount > 0 ? totalDurationSeconds / durationsCount : 0.0;

        return new CampaignWindowMetricsDto(
            Window: window,
            TotalEvaluations: totalEvaluations,
            DispatchedCount: dispatched,
            SkippedCount: skipped,
            CompletedScansCount: completedCount,
            FailedScansCount: failedCount,
            RecoveredStuckCount: recoveredStuck,
            SuccessRatePercentage: successRate,
            AverageScanDurationSeconds: avgDuration
        );
    }
}
