using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
/// Authoritative implementation of the durable campaign scheduler dispatcher.
///
/// INVARIANTS enforced by this class:
///
/// 1. ATOMIC DISPATCH
///    SecurityScanJob INSERT + Campaign cursor UPDATE + CampaignExecutionAuditLog INSERT
///    are committed in a single SaveChanges() call. Either ALL commit or NOTHING commits.
///    A SkippedClaimLost must leave zero job side effects from the losing scheduler.
///
/// 2. OPTIMISTIC CONCURRENCY
///    Campaign UPDATE includes WHERE ScheduleVersion = @expected (via EF ConcurrencyCheck token).
///    DbUpdateConcurrencyException → SkippedClaimLost, no jobs created.
///    Two scheduler instances racing on the same campaign: exactly one wins.
///
/// 3. IDEMPOTENCY KEY
///    CampaignOccurrenceKey = SHA256("v1\n" + CampaignId:D + "\n" + ScheduledOccurrenceUtc:O + "\n" + ScheduleVersion)
///    Stored as 64-character lowercase hex.
///    A UNIQUE index on (CampaignId, CampaignOccurrenceKey) enforces this at the database level.
///    Scheduler retry after ambiguous commit: duplicate key → no second SecurityScanJob.
///
/// 4. MISSED-RUN ALGORITHM
///    if NextRunUtc &lt;= now: dispatch ONE job, then advance cursor to
///    CalculateNextOccurrence(now, schedule) — a future time.
///    Never loop-advance from the old NextRunUtc; that would produce a backlog storm.
///    A campaign offline for 7 days produces exactly 1 catch-up job.
///
/// 5. HEARTBEAT LEASE
///    Recovery considers a job stuck when: Status == Running AND LastHeartbeatUtc &lt; (now - threshold).
///    The live worker defeats recovery by incrementing JobVersion (heartbeat update),
///    causing DbUpdateConcurrencyException in the recovery path.
///
/// 6. FAILURE COUNTER LIFECYCLE
///    Success  → ConsecutiveFailuresCount = 0
///    Failure  → ConsecutiveFailuresCount++
///    Stuck    → ConsecutiveFailuresCount++ (via RecoverStuckJobsAsync)
///    Count &gt;= MaxConsecutiveFailures → AutoPaused
/// </summary>
public sealed class CampaignDispatchService : ICampaignDispatchService
{
    private readonly IPlatformDbContext _db;
    private readonly ICampaignScheduleCalculator _calculator;
    private readonly CampaignSchedulerOptions _options;
    private readonly ILogger<CampaignDispatchService> _logger;

    public CampaignDispatchService(
        IPlatformDbContext db,
        ICampaignScheduleCalculator calculator,
        IOptions<CampaignSchedulerOptions> options,
        ILogger<CampaignDispatchService>? logger = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _calculator = calculator ?? throw new ArgumentNullException(nameof(calculator));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<CampaignDispatchService>.Instance;
    }

    // =========================================================================
    // 1. RunSchedulerTickAsync
    // =========================================================================

    public async Task<CampaignSchedulerTickResult> RunSchedulerTickAsync(CancellationToken ct = default)
    {
        var tickStart = DateTime.UtcNow;
        int evaluated = 0, dispatched = 0, skipped = 0, claimLost = 0, errors = 0;

        if (!_options.GlobalEnabled)
        {
            _logger.LogInformation("CampaignScheduler: GlobalEnabled=false — tick skipped.");
            return new CampaignSchedulerTickResult(0, 0, 0, 0, 0, tickStart, DateTime.UtcNow);
        }

        // Query due campaigns: Active, NextRunUtc <= now
        var dueCampaigns = await _db.ScanCampaigns
            .Include(c => c.SecurityTarget)
            .Where(c => c.Status == CampaignStatus.Active
                     && c.NextRunUtc != null
                     && c.NextRunUtc <= tickStart)
            .OrderBy(c => c.NextRunUtc)
            .Take(_options.MaxCampaignsPerTick)
            .ToListAsync(ct);

        foreach (var campaign in dueCampaigns)
        {
            evaluated++;
            try
            {
                var result = await DispatchCampaignOccurrenceAsync(campaign, tickStart, ct);
                switch (result)
                {
                    case SchedulerDecision.Dispatched:
                    case SchedulerDecision.QueuedNext:
                        dispatched++;
                        break;
                    case SchedulerDecision.SkippedClaimLost:
                        claimLost++;
                        break;
                    default:
                        skipped++;
                        break;
                }
            }
            catch (Exception ex)
            {
                errors++;
                _logger.LogError(ex, "CampaignScheduler: Unexpected error dispatching Campaign '{CampaignId}'.", campaign.Id);
            }
        }

        var tickEnd = DateTime.UtcNow;
        _logger.LogInformation(
            "CampaignScheduler tick complete. Evaluated={Evaluated} Dispatched={Dispatched} Skipped={Skipped} ClaimLost={ClaimLost} Errors={Errors} Duration={DurationMs}ms",
            evaluated, dispatched, skipped, claimLost, errors, (tickEnd - tickStart).TotalMilliseconds);

        return new CampaignSchedulerTickResult(evaluated, dispatched, skipped, claimLost, errors, tickStart, tickEnd);
    }

    // =========================================================================
    // 2. RecoverStuckJobsAsync
    // =========================================================================

    public async Task<int> RecoverStuckJobsAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var stuckCutoff = now.AddMinutes(-_options.StuckJobThresholdMinutes);
        int recovered = 0;

        // Find Running jobs whose heartbeat is stale
        var stuckJobs = await _db.SecurityScanJobs
            .Where(j => j.Status == SecurityScanJobStatus.Running
                     && j.CampaignId != null
                     && j.LastHeartbeatUtc < stuckCutoff)
            .ToListAsync(ct);

        foreach (var job in stuckJobs)
        {
            try
            {
                // Atomically claim the stuck job using JobVersion concurrency token.
                // If the live worker has updated its heartbeat (which also bumps JobVersion),
                // EF will throw DbUpdateConcurrencyException and we correctly do nothing.
                var expectedVersion = job.JobVersion;
                job.Status = SecurityScanJobStatus.TimedOut;
                job.FailureReason = "CAMPAIGN_JOB_STUCK";
                job.CompletedAtUtc = now;
                job.JobVersion = expectedVersion + 1;

                // Load campaign to update failure counter
                var campaign = await _db.ScanCampaigns
                    .FirstOrDefaultAsync(c => c.Id == job.CampaignId, ct);

                var auditLog = new CampaignExecutionAuditLog
                {
                    Id = Guid.NewGuid(),
                    CampaignId = job.CampaignId!.Value,
                    TenantId = campaign?.TenantId ?? Guid.Empty,
                    Decision = SchedulerDecision.RecoveredStuck,
                    TriggerSource = "RecoveryWorker",
                    ScheduleVersion = campaign?.ScheduleVersion ?? 0,
                    EvaluatedAtUtc = now,
                    DispatchedScanJobId = null,
                    Reason = $"Job '{job.Id}' exceeded heartbeat threshold ({_options.StuckJobThresholdMinutes}min). " +
                             $"LastHeartbeatUtc={job.LastHeartbeatUtc:O}. Status set to TimedOut.",
                    MetadataJson = $"{{\"workerId\":\"{job.WorkerInstanceId}\",\"threshold\":{_options.StuckJobThresholdMinutes}}}"
                };

                _db.CampaignExecutionAuditLogs.Add(auditLog);

                if (campaign != null)
                {
                    campaign.ConsecutiveFailuresCount++;
                    campaign.UpdatedAtUtc = now;

                    if (campaign.AutoPauseOnConsecutiveFailures
                        && campaign.ConsecutiveFailuresCount >= campaign.MaxConsecutiveFailures)
                    {
                        campaign.Status = CampaignStatus.AutoPaused;
                        campaign.NextRunUtc = null;
                        campaign.ScheduleVersion++;
                        _logger.LogWarning(
                            "CampaignScheduler: Campaign '{CampaignId}' AutoPaused after {Count} consecutive failures (stuck job recovery).",
                            campaign.Id, campaign.ConsecutiveFailuresCount);
                    }
                }

                await _db.SaveChangesAsync(ct);
                recovered++;

                _logger.LogWarning(
                    "CampaignScheduler: Stuck job '{JobId}' transitioned to TimedOut (worker={WorkerId}, lastHeartbeat={LastHeartbeat:O}).",
                    job.Id, job.WorkerInstanceId, job.LastHeartbeatUtc);
            }
            catch (DbUpdateConcurrencyException)
            {
                // The live worker heartbeated (and incremented JobVersion) before our recovery attempt.
                // This is the correct and desired outcome — the worker is alive.
                _logger.LogInformation(
                    "CampaignScheduler: Recovery race lost for job '{JobId}' — live worker heartbeated first, job remains Running.",
                    job.Id);

                // Detach stale entity state so the context is clean for the next iteration
                _db.ChangeTracker.Entries()
                    .Where(e => e.State != EntityState.Unchanged)
                    .ToList()
                    .ForEach(e => e.State = EntityState.Unchanged);
            }
        }

        return recovered;
    }

    // =========================================================================
    // 3. ProcessJobOutcomeAsync
    // =========================================================================

    public async Task ProcessJobOutcomeAsync(Guid scanJobId, bool success, CancellationToken ct = default)
    {
        var job = await _db.SecurityScanJobs
            .AsNoTracking()
            .FirstOrDefaultAsync(j => j.Id == scanJobId, ct);

        if (job?.CampaignId == null)
        {
            // Not a campaign job — no-op
            return;
        }

        var campaign = await _db.ScanCampaigns
            .FirstOrDefaultAsync(c => c.Id == job.CampaignId, ct);

        if (campaign == null)
        {
            _logger.LogWarning("CampaignDispatch.ProcessJobOutcome: Campaign '{CampaignId}' not found for job '{JobId}'.",
                job.CampaignId, scanJobId);
            return;
        }

        var now = DateTime.UtcNow;

        if (success)
        {
            // INVARIANT: Successful execution resets the consecutive failure counter.
            // A campaign that has had historical failures but recovers must not
            // accumulate towards AutoPause indefinitely.
            campaign.ConsecutiveFailuresCount = 0;
            campaign.UpdatedAtUtc = now;

            _logger.LogInformation(
                "CampaignDispatch: Job '{JobId}' succeeded for Campaign '{CampaignId}'. ConsecutiveFailuresCount reset to 0.",
                scanJobId, campaign.Id);
        }
        else
        {
            campaign.ConsecutiveFailuresCount++;
            campaign.UpdatedAtUtc = now;

            _logger.LogWarning(
                "CampaignDispatch: Job '{JobId}' failed for Campaign '{CampaignId}'. ConsecutiveFailuresCount={Count}.",
                scanJobId, campaign.Id, campaign.ConsecutiveFailuresCount);

            if (campaign.AutoPauseOnConsecutiveFailures
                && campaign.ConsecutiveFailuresCount >= campaign.MaxConsecutiveFailures)
            {
                campaign.Status = CampaignStatus.AutoPaused;
                campaign.NextRunUtc = null;
                campaign.ScheduleVersion++;

                _logger.LogWarning(
                    "CampaignDispatch: Campaign '{CampaignId}' AutoPaused after {Count} consecutive failures.",
                    campaign.Id, campaign.ConsecutiveFailuresCount);
            }
        }

        await _db.SaveChangesAsync(ct);
    }

    // =========================================================================
    // Private: Core dispatch logic
    // =========================================================================

    private async Task<SchedulerDecision> DispatchCampaignOccurrenceAsync(
        ScanCampaign campaign,
        DateTime now,
        CancellationToken ct)
    {
        // Guard: target must be enabled
        if (campaign.SecurityTarget == null || !campaign.SecurityTarget.Enabled)
        {
            await RecordAuditAsync(campaign, SchedulerDecision.SkippedTargetDisabled, null, now,
                "Associated SecurityTarget is disabled or missing.", null, ct);
            // Advance the cursor so we don't hammer this every tick
            await AdvanceCursorOnlyAsync(campaign, now, ct);
            return SchedulerDecision.SkippedTargetDisabled;
        }

        // INVARIANT: Compute the canonical deterministic occurrence key BEFORE any DB writes.
        // Key format: SHA256("v1\n" + CampaignId:D + "\n" + ScheduledOccurrenceUtc:O + "\n" + ScheduleVersion)
        // Output: 64-character lowercase hex.
        var scheduledOccurrenceUtc = campaign.NextRunUtc!.Value;
        var occurrenceKey = ComputeOccurrenceKey(campaign.Id, scheduledOccurrenceUtc, campaign.ScheduleVersion);

        // IDEMPOTENCY GUARD: Check if this occurrence was already dispatched (e.g., after network failure + retry)
        var existingJob = await _db.SecurityScanJobs
            .AsNoTracking()
            .FirstOrDefaultAsync(j => j.CampaignId == campaign.Id
                                   && j.CampaignOccurrenceKey == occurrenceKey, ct);

        if (existingJob != null)
        {
            _logger.LogInformation(
                "CampaignScheduler: Campaign '{CampaignId}' occurrence key '{Key}' already dispatched as job '{JobId}'. Idempotency guard — skipping.",
                campaign.Id, occurrenceKey, existingJob.Id);

            // Still advance the cursor so the scheduler doesn't re-evaluate this same occurrence next tick
            await AdvanceCursorOnlyAsync(campaign, now, ct);
            return SchedulerDecision.Dispatched; // Occurrence already handled
        }

        // Evaluate concurrency policy against in-flight jobs
        var activeJobs = await _db.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id
                     && (j.Status == SecurityScanJobStatus.Running || j.Status == SecurityScanJobStatus.Queued))
            .ToListAsync(ct);

        var runningJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Running);
        var queuedJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Queued);

        if (runningJob != null)
        {
            switch (campaign.ConcurrencyPolicy)
            {
                case CampaignConcurrencyPolicy.SkipIfRunning:
                    await RecordAuditAsync(campaign, SchedulerDecision.SkippedAlreadyRunning, null, now,
                        $"Job '{runningJob.Id}' is Running. ConcurrencyPolicy=SkipIfRunning.", null, ct);
                    await AdvanceCursorOnlyAsync(campaign, now, ct);
                    return SchedulerDecision.SkippedAlreadyRunning;

                case CampaignConcurrencyPolicy.ForbidConcurrent:
                    await RecordAuditAsync(campaign, SchedulerDecision.RejectedConcurrent, null, now,
                        $"Job '{runningJob.Id}' is Running. ConcurrencyPolicy=ForbidConcurrent.", null, ct);
                    await AdvanceCursorOnlyAsync(campaign, now, ct);
                    return SchedulerDecision.RejectedConcurrent;

                case CampaignConcurrencyPolicy.QueueNext:
                    if (queuedJob != null)
                    {
                        await RecordAuditAsync(campaign, SchedulerDecision.SkippedQueueFull, null, now,
                            $"Pending job '{queuedJob.Id}' already queued. QueueNext depth capped at 1.", null, ct);
                        await AdvanceCursorOnlyAsync(campaign, now, ct);
                        return SchedulerDecision.SkippedQueueFull;
                    }
                    // Fall through to dispatch a Queued job (no cursor advance yet — running job still active)
                    return await AtomicDispatchAsync(campaign, scheduledOccurrenceUtc, occurrenceKey, now, true, ct);
            }
        }

        // No running jobs — dispatch immediately
        return await AtomicDispatchAsync(campaign, scheduledOccurrenceUtc, occurrenceKey, now, false, ct);
    }

    /// <summary>
    /// Performs the fully atomic dispatch operation.
    /// ALL of the following succeed or fail as a single database transaction via SaveChanges():
    ///   1. SecurityScanJob INSERT (with CampaignOccurrenceKey)
    ///   2. Campaign UPDATE (ScheduleVersion++, NextRunUtc advanced to next FUTURE occurrence)
    ///   3. CampaignExecutionAuditLog INSERT
    ///
    /// If another scheduler instance wins the optimistic concurrency race, EF raises
    /// DbUpdateConcurrencyException. We catch it, log SkippedClaimLost, and return with
    /// zero side effects from the losing scheduler instance.
    /// </summary>
    private async Task<SchedulerDecision> AtomicDispatchAsync(
        ScanCampaign campaign,
        DateTime scheduledOccurrenceUtc,
        string occurrenceKey,
        DateTime now,
        bool isQueueNext,
        CancellationToken ct)
    {
        var decision = isQueueNext ? SchedulerDecision.QueuedNext : SchedulerDecision.Dispatched;
        var triggeredBy = "CampaignScheduler";

        var newJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = campaign.RepositoryId,
            TargetId = campaign.SecurityTargetId,
            TargetUrl = campaign.SecurityTarget!.BaseUrl,
            ScanProfile = campaign.ScanProfile,
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = Guid.Empty, // System-initiated
            TriggeredBy = triggeredBy,
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = now,
            CampaignOccurrenceKey = occurrenceKey,
            JobVersion = 1
        };

        _db.SecurityScanJobs.Add(newJob);

        // INVARIANT: Advance cursor to the NEXT FUTURE occurrence from 'now' (not from old NextRunUtc).
        // This ensures a campaign offline for any duration produces exactly ONE catch-up job.
        var nextOccurrence = _calculator.CalculateNextOccurrence(
            campaign.ScheduleType,
            campaign.CronExpression,
            campaign.IntervalDuration,
            campaign.TimeZoneId,
            now);

        if (!isQueueNext)
        {
            // Only advance cursor and counters when dispatching directly (not when just queuing behind a running job)
            campaign.ScheduleVersion++;
            campaign.NextRunUtc = nextOccurrence.IsValid ? nextOccurrence.NextOccurrenceUtc : null;
            campaign.LastRunUtc = now;
            campaign.LastScanJobId = newJob.Id;
            campaign.TotalRunsCount++;
            campaign.LastCampaignOccurrenceKey = occurrenceKey;
            campaign.UpdatedAtUtc = now;
        }
        else
        {
            // QueueNext: don't advance cursor (running job still owns the current window)
            campaign.LastCampaignOccurrenceKey = occurrenceKey;
            campaign.UpdatedAtUtc = now;
        }

        var auditLog = new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            TenantId = campaign.TenantId,
            Decision = decision,
            TriggerSource = triggeredBy,
            ScheduleVersion = campaign.ScheduleVersion,
            EvaluatedAtUtc = now,
            DispatchedScanJobId = newJob.Id,
            Reason = isQueueNext
                ? $"QueueNext: enqueued job '{newJob.Id}' behind running job. OccurrenceKey={occurrenceKey}."
                : $"Dispatched job '{newJob.Id}' for scheduled occurrence {scheduledOccurrenceUtc:O}. NextRunUtc={campaign.NextRunUtc:O}.",
            MetadataJson = $"{{\"occurrenceKey\":\"{occurrenceKey}\",\"scheduledOccurrenceUtc\":\"{scheduledOccurrenceUtc:O}\"}}"
        };

        _db.CampaignExecutionAuditLogs.Add(auditLog);

        try
        {
            // ▼▼▼ SINGLE ATOMIC SaveChanges — the dispatch invariant ▼▼▼
            await _db.SaveChangesAsync(ct);

            _logger.LogInformation(
                "CampaignScheduler: {Decision} Campaign '{CampaignId}' → Job '{JobId}' (occurrence={Occurrence:O}, version={Version}).",
                decision, campaign.Id, newJob.Id, scheduledOccurrenceUtc, campaign.ScheduleVersion);

            return decision;
        }
        catch (DbUpdateConcurrencyException)
        {
            // INVARIANT: SkippedClaimLost — another scheduler instance claimed this campaign first.
            // The DbContext change tracker still has our unsaved changes, but since we're not
            // calling SaveChanges again, zero side effects reach the database.
            _logger.LogInformation(
                "CampaignScheduler: SkippedClaimLost for Campaign '{CampaignId}' (occurrence={Occurrence:O}). " +
                "Another scheduler instance won the optimistic concurrency race. No job created.",
                campaign.Id, scheduledOccurrenceUtc);

            // Record audit in a fresh context operation (separate from the failed transaction)
            try
            {
                // Detach all stale tracked entities before recording the skip
                _db.ChangeTracker.Entries()
                    .Where(e => e.State != EntityState.Unchanged)
                    .ToList()
                    .ForEach(e => e.State = EntityState.Unchanged);

                var skipAudit = new CampaignExecutionAuditLog
                {
                    Id = Guid.NewGuid(),
                    CampaignId = campaign.Id,
                    TenantId = campaign.TenantId,
                    Decision = SchedulerDecision.SkippedClaimLost,
                    TriggerSource = "CampaignScheduler",
                    ScheduleVersion = campaign.ScheduleVersion,
                    EvaluatedAtUtc = now,
                    DispatchedScanJobId = null,
                    Reason = $"Optimistic concurrency race lost for occurrence {scheduledOccurrenceUtc:O}. Another instance dispatched first.",
                    MetadataJson = $"{{\"occurrenceKey\":\"{occurrenceKey}\"}}"
                };
                _db.CampaignExecutionAuditLogs.Add(skipAudit);
                await _db.SaveChangesAsync(ct);
            }
            catch (Exception auditEx)
            {
                _logger.LogWarning(auditEx, "CampaignScheduler: Failed to write SkippedClaimLost audit for Campaign '{CampaignId}'.", campaign.Id);
            }

            return SchedulerDecision.SkippedClaimLost;
        }
    }

    /// <summary>
    /// Advances the campaign cursor without dispatching a job.
    /// Used when the occurrence is skipped (target disabled, concurrency policy, etc.)
    /// to prevent the scheduler from re-evaluating the same overdue occurrence on the next tick.
    /// </summary>
    private async Task AdvanceCursorOnlyAsync(ScanCampaign campaign, DateTime now, CancellationToken ct)
    {
        try
        {
            var nextOccurrence = _calculator.CalculateNextOccurrence(
                campaign.ScheduleType,
                campaign.CronExpression,
                campaign.IntervalDuration,
                campaign.TimeZoneId,
                now);

            campaign.NextRunUtc = nextOccurrence.IsValid ? nextOccurrence.NextOccurrenceUtc : null;
            campaign.UpdatedAtUtc = now;

            await _db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CampaignScheduler: Failed to advance cursor for Campaign '{CampaignId}'.", campaign.Id);
        }
    }

    private async Task RecordAuditAsync(
        ScanCampaign campaign,
        SchedulerDecision decision,
        Guid? jobId,
        DateTime now,
        string reason,
        string? metadataJson,
        CancellationToken ct)
    {
        try
        {
            _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
            {
                Id = Guid.NewGuid(),
                CampaignId = campaign.Id,
                TenantId = campaign.TenantId,
                Decision = decision,
                TriggerSource = "CampaignScheduler",
                ScheduleVersion = campaign.ScheduleVersion,
                EvaluatedAtUtc = now,
                DispatchedScanJobId = jobId,
                Reason = reason,
                MetadataJson = metadataJson
            });
            await _db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CampaignScheduler: Failed to write audit log [{Decision}] for Campaign '{CampaignId}'.", decision, campaign.Id);
        }
    }

    // =========================================================================
    // Canonical Occurrence Key
    // =========================================================================

    /// <summary>
    /// Computes the canonical, versionable idempotency key for a scheduled occurrence.
    ///
    /// Format (v1):
    ///   SHA256("v1\n" + campaignId:D + "\n" + scheduledOccurrenceUtc:O + "\n" + scheduleVersion)
    ///
    /// Output: 64-character lowercase hexadecimal string.
    ///
    /// The "v1\n" prefix makes the hash contract explicit and versionable.
    /// Using round-trip UTC format ("O") eliminates timezone/precision ambiguity.
    /// Newline delimiters prevent field-concatenation collisions.
    /// </summary>
    public static string ComputeOccurrenceKey(Guid campaignId, DateTime scheduledOccurrenceUtc, long scheduleVersion)
    {
        var input = $"v1\n{campaignId:D}\n{scheduledOccurrenceUtc:O}\n{scheduleVersion}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
