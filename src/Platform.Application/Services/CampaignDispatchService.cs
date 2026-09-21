using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Contracts;
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
///    CampaignOccurrenceKey = SHA256("v1\n" + CampaignId:D + "\n" + CanonicalUtcMicroseconds(ScheduledOccurrenceUtc):O + "\n" + ScheduleVersion)
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
/// 6. ORDERED FAILURE COUNTER LIFECYCLE
///    Terminal outcomes are applied in deterministic completion order.
///    Success  → ConsecutiveFailuresCount = 0
///    Failure (including recovered timeout) → ConsecutiveFailuresCount++
///    Count &gt;= MaxConsecutiveFailures → AutoPaused
/// </summary>
public sealed class CampaignDispatchService : ICampaignDispatchService
{
    private const string OccurrenceKeyConstraintName = "IX_security_scan_jobs_campaign_occurrence_key";

    private readonly IPlatformDbContext _db;
    private readonly ICampaignScheduleCalculator _calculator;
    private readonly CampaignSchedulerOptions _options;
    private readonly ITenantContext _tenantContext;
    private readonly ILogger<CampaignDispatchService> _logger;
    private readonly IDatabaseErrorClassifier _databaseErrorClassifier;

    public CampaignDispatchService(
        IPlatformDbContext db,
        ICampaignScheduleCalculator calculator,
        IOptions<CampaignSchedulerOptions> options,
        ITenantContext tenantContext,
        IDatabaseErrorClassifier databaseErrorClassifier,
        ILogger<CampaignDispatchService>? logger = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _calculator = calculator ?? throw new ArgumentNullException(nameof(calculator));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));

        // Required: a missing registration must fail fast instead of silently disabling
        // duplicate-occurrence and ambiguous-commit classification.
        _databaseErrorClassifier = databaseErrorClassifier
            ?? throw new ArgumentNullException(nameof(databaseErrorClassifier));
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
            .Where(c => c.TenantId == _tenantContext.TenantId
                     && c.Status == CampaignStatus.Active
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
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
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
        var recovered = 0;
        var recoveredCampaignJobIds = new List<Guid>();

        // Find Running jobs whose heartbeat is stale.
        var stuckJobs = await _db.SecurityScanJobs
            .Where(j => j.TenantId == _tenantContext.TenantId
                     && j.Status == SecurityScanJobStatus.Running
                     && j.LastHeartbeatUtc < stuckCutoff)
            .ToListAsync(ct);

        foreach (var job in stuckJobs)
        {
            CampaignExecutionAuditLog? auditLog = null;

            try
            {
                // JobVersion fences this terminal transition against a live heartbeat.
                var expectedVersion = job.JobVersion;
                job.Status = SecurityScanJobStatus.TimedOut;
                job.FailureReason = "CAMPAIGN_JOB_STUCK";
                job.CompletedAtUtc = now;
                job.CampaignOutcomeProcessedAtUtc = null;
                job.JobVersion = expectedVersion + 1;

                if (job.CampaignId.HasValue)
                {
                    var campaignSnapshot = await _db.ScanCampaigns
                        .AsNoTracking()
                        .FirstOrDefaultAsync(c => c.Id == job.CampaignId.Value
                            && c.TenantId == job.TenantId, ct);

                    auditLog = new CampaignExecutionAuditLog
                    {
                        Id = Guid.NewGuid(),
                        CampaignId = job.CampaignId.Value,
                        TenantId = job.TenantId,
                        Decision = SchedulerDecision.RecoveredStuck,
                        TriggerSource = "RecoveryWorker",
                        ScheduleVersion = campaignSnapshot?.ScheduleVersion ?? 0,
                        EvaluatedAtUtc = now,
                        DispatchedScanJobId = job.Id,
                        Reason = $"Job '{job.Id}' exceeded heartbeat threshold ({_options.StuckJobThresholdMinutes}min). " +
                                 $"LastHeartbeatUtc={job.LastHeartbeatUtc:O}. Status set to TimedOut.",
                        MetadataJson = $"{{\"workerId\":\"{job.WorkerInstanceId}\",\"threshold\":{_options.StuckJobThresholdMinutes}}}"
                    };

                    _db.CampaignExecutionAuditLogs.Add(auditLog);
                }

                // Terminal job state and recovery audit commit atomically. Outcome accounting
                // remains pending and is applied through ProcessJobOutcomeAsync below.
                await _db.SaveChangesAsync(ct);
                recovered++;

                if (job.CampaignId.HasValue)
                {
                    recoveredCampaignJobIds.Add(job.Id);
                }

                _logger.LogWarning(
                    "CampaignScheduler: Stuck job '{JobId}' transitioned to TimedOut (worker={WorkerId}, lastHeartbeat={LastHeartbeat:O}).",
                    job.Id,
                    job.WorkerInstanceId,
                    job.LastHeartbeatUtc);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogInformation(
                    "CampaignScheduler: Recovery race lost for job '{JobId}' — its durable state changed before timeout recovery committed.",
                    job.Id);

                foreach (var entry in ex.Entries)
                {
                    entry.State = EntityState.Detached;
                }

                if (auditLog != null)
                {
                    var auditEntry = _db.ChangeTracker.Entries<CampaignExecutionAuditLog>()
                        .FirstOrDefault(entry => ReferenceEquals(entry.Entity, auditLog));
                    if (auditEntry != null)
                    {
                        auditEntry.State = EntityState.Detached;
                    }
                }
            }
        }

        foreach (var scanJobId in recoveredCampaignJobIds)
        {
            try
            {
                await ProcessJobOutcomeAsync(scanJobId, success: false, ct: ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                _logger.LogInformation(
                    "CampaignScheduler: Outcome accounting for recovered job '{JobId}' was deferred by a concurrent campaign update and remains retryable.",
                    scanJobId);

                _db.ChangeTracker.Entries()
                    .Where(entry => entry.State != EntityState.Unchanged)
                    .ToList()
                    .ForEach(entry => entry.State = EntityState.Detached);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "CampaignScheduler: Outcome accounting for recovered job '{JobId}' failed and remains pending for reconciliation.",
                    scanJobId);

                _db.ChangeTracker.Entries()
                    .Where(entry => entry.State != EntityState.Unchanged)
                    .ToList()
                    .ForEach(entry => entry.State = EntityState.Detached);
            }
        }

        return recovered;
    }

    // =========================================================================
    // 3. ProcessJobOutcomeAsync
    // =========================================================================

    public async Task ProcessJobOutcomeAsync(Guid scanJobId, bool success, CancellationToken ct = default)
    {
        // Kept for interface compatibility. Durable job status is the sole outcome authority.
        _ = success;

        var durableJob = await _db.SecurityScanJobs
            .AsNoTracking()
            .FirstOrDefaultAsync(j => j.Id == scanJobId
                && j.TenantId == _tenantContext.TenantId, ct);

        if (durableJob?.CampaignId == null)
        {
            // Not a campaign job — no-op.
            return;
        }

        if (durableJob.CampaignOutcomeProcessedAtUtc.HasValue)
        {
            _logger.LogDebug(
                "CampaignDispatch.ProcessJobOutcome: Job '{JobId}' outcome was already applied at {ProcessedAtUtc:O}.",
                scanJobId,
                durableJob.CampaignOutcomeProcessedAtUtc);
            return;
        }

        bool? durableSuccess = durableJob.Status switch
        {
            SecurityScanJobStatus.Completed or SecurityScanJobStatus.CompletedWithWarnings => true,
            SecurityScanJobStatus.Partial
                or SecurityScanJobStatus.Failed
                or SecurityScanJobStatus.Cancelled
                or SecurityScanJobStatus.TimedOut
                or SecurityScanJobStatus.Blocked => false,
            SecurityScanJobStatus.Queued
                or SecurityScanJobStatus.Validating
                or SecurityScanJobStatus.Running => null,
            _ => null
        };

        if (!durableSuccess.HasValue)
        {
            _logger.LogWarning(
                "CampaignDispatch.ProcessJobOutcome: Job '{JobId}' is not terminal (status '{Status}'). Outcome deferred.",
                scanJobId,
                durableJob.Status);
            return;
        }

        // Outcomes for one campaign are applied strictly in durable completion order.
        // Concurrent reconcilers may race on the same head, but cannot skip past it.
        var earliestPendingJobId = await _db.SecurityScanJobs
            .AsNoTracking()
            .Where(j => j.CampaignId == durableJob.CampaignId
                     && j.CampaignOutcomeProcessedAtUtc == null
                     && (j.Status == SecurityScanJobStatus.Completed
                         || j.Status == SecurityScanJobStatus.CompletedWithWarnings
                         || j.Status == SecurityScanJobStatus.Partial
                         || j.Status == SecurityScanJobStatus.Failed
                         || j.Status == SecurityScanJobStatus.Cancelled
                         || j.Status == SecurityScanJobStatus.TimedOut
                         || j.Status == SecurityScanJobStatus.Blocked))
            .OrderBy(j => j.CompletedAtUtc ?? j.CreatedAtUtc)
            .ThenBy(j => j.CreatedAtUtc)
            .ThenBy(j => j.Id)
            .Select(j => (Guid?)j.Id)
            .FirstOrDefaultAsync(ct);

        if (earliestPendingJobId != scanJobId)
        {
            _logger.LogDebug(
                "CampaignDispatch.ProcessJobOutcome: Job '{JobId}' is not the earliest pending terminal outcome for Campaign '{CampaignId}'. Outcome deferred.",
                scanJobId,
                durableJob.CampaignId);
            return;
        }

        // Recovery can call this method with the job already tracked. Replace that instance
        // with the freshly loaded durable snapshot so status and JobVersion are authoritative.
        var existingJobEntry = _db.ChangeTracker.Entries<SecurityScanJob>()
            .FirstOrDefault(entry => entry.Entity.Id == scanJobId);
        if (existingJobEntry != null)
        {
            existingJobEntry.State = EntityState.Detached;
        }
        _db.SecurityScanJobs.Attach(durableJob);

        var campaign = await _db.ScanCampaigns
            .FirstOrDefaultAsync(c => c.Id == durableJob.CampaignId.Value
                && c.TenantId == durableJob.TenantId, ct);

        var now = DateTime.UtcNow;
        if (campaign == null)
        {
            _logger.LogWarning(
                "CampaignDispatch.ProcessJobOutcome: Campaign '{CampaignId}' not found for job '{JobId}'.",
                durableJob.CampaignId,
                scanJobId);

            // Prevent a permanently orphaned job from being retried on every reconciliation pass.
            durableJob.CampaignOutcomeProcessedAtUtc = now;
            durableJob.JobVersion++;
            await _db.SaveChangesAsync(ct);
            return;
        }

        if (durableSuccess.Value)
        {
            campaign.ConsecutiveFailuresCount = 0;
            campaign.UpdatedAtUtc = now;

            _logger.LogInformation(
                "CampaignDispatch: Job '{JobId}' succeeded for Campaign '{CampaignId}'. ConsecutiveFailuresCount reset to 0.",
                scanJobId,
                campaign.Id);
        }
        else
        {
            campaign.ConsecutiveFailuresCount++;
            campaign.UpdatedAtUtc = now;

            _logger.LogWarning(
                "CampaignDispatch: Job '{JobId}' failed for Campaign '{CampaignId}'. ConsecutiveFailuresCount={Count}.",
                scanJobId,
                campaign.Id,
                campaign.ConsecutiveFailuresCount);

            if (campaign.AutoPauseOnConsecutiveFailures
                && campaign.ConsecutiveFailuresCount >= campaign.MaxConsecutiveFailures)
            {
                campaign.Status = CampaignStatus.AutoPaused;
                campaign.NextRunUtc = null;

                _logger.LogWarning(
                    "CampaignDispatch: Campaign '{CampaignId}' AutoPaused after {Count} consecutive failures.",
                    campaign.Id,
                    campaign.ConsecutiveFailuresCount);
            }
        }

        // Campaign mutation and durable per-job marker share one optimistic transaction.
        campaign.ScheduleVersion++;
        durableJob.CampaignOutcomeProcessedAtUtc = now;
        durableJob.JobVersion++;
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
        // Key format: SHA256("v1\n" + CampaignId:D + "\n" + CanonicalUtcMicroseconds(ScheduledOccurrenceUtc):O + "\n" + ScheduleVersion)
        // Output: 64-character lowercase hex.
        var scheduledOccurrenceUtc = campaign.NextRunUtc!.Value;
        var occurrenceKey = ComputeOccurrenceKey(campaign.Id, scheduledOccurrenceUtc, campaign.ScheduleVersion);
        var attempt = new DispatchAttempt(
            campaign.Id,
            campaign.TenantId,
            campaign.RepositoryId,
            campaign.SecurityTargetId,
            campaign.SecurityTarget.BaseUrl,
            campaign.ScanProfile,
            campaign.ScheduleType,
            campaign.CronExpression,
            campaign.IntervalDuration,
            campaign.TimeZoneId,
            campaign.ScheduleVersion,
            campaign.TotalRunsCount,
            scheduledOccurrenceUtc,
            occurrenceKey);

        // A retry may observe a job after an ambiguous commit acknowledgement. A job row
        // alone is not enough: only the complete atomic job/campaign/audit tuple proves that
        // this occurrence was durably dispatched.
        var existingJobId = await _db.SecurityScanJobs
            .AsNoTracking()
            .Where(j => j.CampaignId == campaign.Id
                     && j.CampaignOccurrenceKey == occurrenceKey)
            .Select(j => (Guid?)j.Id)
            .FirstOrDefaultAsync(ct);

        if (existingJobId.HasValue)
        {
            var committedDecision = await TryGetCommittedDispatchDecisionAsync(attempt, null, ct);
            if (!committedDecision.HasValue)
            {
                throw new InvalidOperationException(
                    $"Campaign '{campaign.Id}' occurrence '{occurrenceKey}' has a scan job " +
                    "without the complete atomic campaign and dispatch-audit state.");
            }

            _logger.LogInformation(
                "CampaignScheduler: Campaign '{CampaignId}' occurrence key '{Key}' is already fully committed as job '{JobId}'. Idempotency guard — skipping.",
                campaign.Id,
                occurrenceKey,
                existingJobId.Value);

            return committedDecision.Value;
        }

        // Evaluate concurrency policy against in-flight jobs
        var activeJobs = await _db.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id
                     && (j.Status == SecurityScanJobStatus.Running || j.Status == SecurityScanJobStatus.Queued))
            .ToListAsync(ct);

        var runningJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Running);
        var queuedJob = activeJobs.FirstOrDefault(j => j.Status == SecurityScanJobStatus.Queued);

        // QueueNext has one durable queued slot even during the terminal-outcome gap.
        // An occupied slot consumes this scheduled occurrence and advances the cursor.
        if (campaign.ConcurrencyPolicy == CampaignConcurrencyPolicy.QueueNext && queuedJob != null)
        {
            await RecordAuditAsync(campaign, SchedulerDecision.SkippedQueueFull, null, now,
                $"Pending job '{queuedJob.Id}' already queued. QueueNext depth capped at 1.", null, ct);
            await AdvanceCursorOnlyAsync(campaign, now, ct);
            return SchedulerDecision.SkippedQueueFull;
        }

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
                    return await AtomicDispatchAsync(campaign, attempt, now, true, ct);
            }
        }

        // No running job and no occupied QueueNext slot — dispatch immediately.
        return await AtomicDispatchAsync(campaign, attempt, now, false, ct);
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
        DispatchAttempt attempt,
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
            TenantId = campaign.TenantId,
            RequestedByUserId = null, // System-initiated
            TriggeredBy = triggeredBy,
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = now,
            CampaignOccurrenceKey = attempt.OccurrenceKey,
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

        // Every dispatched job consumes its scheduled occurrence, including QueueNext.
        // Cursor, token, counters, occurrence key, job, and audit commit atomically.
        campaign.ScheduleVersion++;
        campaign.NextRunUtc = nextOccurrence.IsValid ? nextOccurrence.NextOccurrenceUtc : null;
        campaign.LastRunUtc = now;
        campaign.LastScanJobId = newJob.Id;
        campaign.TotalRunsCount++;
        campaign.LastCampaignOccurrenceKey = attempt.OccurrenceKey;
        campaign.UpdatedAtUtc = now;

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
                ? $"QueueNext: enqueued job '{newJob.Id}' behind running job. OccurrenceKey={attempt.OccurrenceKey}."
                : $"Dispatched job '{newJob.Id}' for scheduled occurrence {attempt.ScheduledOccurrenceUtc:O}. NextRunUtc={campaign.NextRunUtc:O}.",
            MetadataJson = $"{{\"occurrenceKey\":\"{attempt.OccurrenceKey}\",\"scheduledOccurrenceUtc\":\"{attempt.ScheduledOccurrenceUtc:O}\"}}"
        };

        _db.CampaignExecutionAuditLogs.Add(auditLog);

        try
        {
            // ▼▼▼ SINGLE ATOMIC SaveChanges — the dispatch invariant ▼▼▼
            await _db.SaveChangesAsync(ct);

            _logger.LogInformation(
                "CampaignScheduler: {Decision} Campaign '{CampaignId}' → Job '{JobId}' (occurrence={Occurrence:O}, version={Version}).",
                decision, campaign.Id, newJob.Id, attempt.ScheduledOccurrenceUtc, campaign.ScheduleVersion);

            return decision;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            DiscardPendingChanges();
            var committedDecision = await TryGetCommittedDispatchDecisionAsync(attempt, decision, ct);
            if (committedDecision != decision)
            {
                _logger.LogWarning(
                    ex,
                    "CampaignScheduler: Campaign '{CampaignId}' encountered a stale schedule token, but occurrence '{OccurrenceKey}' has no complete competing dispatch state.",
                    campaign.Id,
                    attempt.OccurrenceKey);
                throw;
            }

            _logger.LogInformation(
                "CampaignScheduler: SkippedClaimLost for Campaign '{CampaignId}' (occurrence={Occurrence:O}). " +
                "Another scheduler committed the complete job, campaign cursor, and audit state.",
                campaign.Id,
                attempt.ScheduledOccurrenceUtc);

            return await RecordClaimLostAsync(
                campaign,
                attempt.ScheduledOccurrenceUtc,
                attempt.OccurrenceKey,
                attempt.ExpectedScheduleVersion,
                now,
                "Optimistic concurrency token was stale and the competing atomic dispatch was verified.",
                ct);
        }
        catch (OperationCanceledException)
        {
            // Cancellation must retain its normal propagation semantics, but the shared
            // context must not carry this atomic batch into another campaign.
            DiscardPendingChanges();
            throw;
        }
        catch (Exception ex)
        {
            var expectedUniqueViolation = _databaseErrorClassifier.IsUniqueConstraintViolation(
                ex,
                OccurrenceKeyConstraintName);
            var potentiallyAmbiguousCommit = _databaseErrorClassifier
                .IsPotentiallyAmbiguousCommitFailure(ex);

            // EF can surface provider failures either through DbUpdateException or directly
            // while committing. Always detach the atomic batch before reconciliation or
            // rethrow so a later campaign cannot replay any failed tracked writes.
            DiscardPendingChanges();

            if (!expectedUniqueViolation && !potentiallyAmbiguousCommit)
            {
                _logger.LogWarning(
                    ex,
                    "CampaignScheduler: Database operation failed for Campaign '{CampaignId}' and was not eligible for claim reconciliation.",
                    campaign.Id);
                throw;
            }

            var committedDecision = await TryGetCommittedDispatchDecisionAsync(attempt, decision, ct);
            if (committedDecision != decision)
            {
                _logger.LogWarning(
                    ex,
                    "CampaignScheduler: Database operation failed for Campaign '{CampaignId}'. ExpectedOccurrenceConstraint={ExpectedOccurrenceConstraint}; PotentiallyAmbiguousCommit={PotentiallyAmbiguousCommit}; CompleteCompetingState=false.",
                    campaign.Id,
                    expectedUniqueViolation,
                    potentiallyAmbiguousCommit);
                throw;
            }

            _logger.LogInformation(
                ex,
                "CampaignScheduler: SkippedClaimLost for Campaign '{CampaignId}' because occurrence '{OccurrenceKey}' has a complete committed dispatch. ExpectedOccurrenceConstraint={ExpectedOccurrenceConstraint}; PotentiallyAmbiguousCommit={PotentiallyAmbiguousCommit}.",
                campaign.Id,
                attempt.OccurrenceKey,
                expectedUniqueViolation,
                potentiallyAmbiguousCommit);

            return await RecordClaimLostAsync(
                campaign,
                attempt.ScheduledOccurrenceUtc,
                attempt.OccurrenceKey,
                attempt.ExpectedScheduleVersion,
                now,
                expectedUniqueViolation
                    ? $"PostgreSQL constraint '{OccurrenceKeyConstraintName}' rejected the duplicate and the competing atomic dispatch was verified."
                    : "A complete competing atomic dispatch was verified after an ambiguous commit acknowledgement failure.",
                ct);
        }
    }

    private async Task<SchedulerDecision> RecordClaimLostAsync(
        ScanCampaign campaign,
        DateTime scheduledOccurrenceUtc,
        string occurrenceKey,
        long expectedScheduleVersion,
        DateTime now,
        string reason,
        CancellationToken ct)
    {
        try
        {
            DiscardPendingChanges();

            _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
            {
                Id = Guid.NewGuid(),
                CampaignId = campaign.Id,
                TenantId = campaign.TenantId,
                Decision = SchedulerDecision.SkippedClaimLost,
                TriggerSource = "CampaignScheduler",
                ScheduleVersion = expectedScheduleVersion,
                EvaluatedAtUtc = now,
                DispatchedScanJobId = null,
                Reason = $"Claim lost for occurrence {scheduledOccurrenceUtc:O}. {reason}",
                MetadataJson = $"{{\"occurrenceKey\":\"{occurrenceKey}\"}}"
            });
            await _db.SaveChangesAsync(ct);
        }
        catch (Exception auditEx)
        {
            // A failed best-effort audit must not be replayed by a later campaign save.
            DiscardPendingChanges();
            _logger.LogWarning(
                auditEx,
                "CampaignScheduler: Failed to write SkippedClaimLost audit for Campaign '{CampaignId}'.",
                campaign.Id);
        }

        return SchedulerDecision.SkippedClaimLost;
    }

    private async Task<SchedulerDecision?> TryGetCommittedDispatchDecisionAsync(
        DispatchAttempt attempt,
        SchedulerDecision? expectedDecision,
        CancellationToken ct)
    {
        try
        {
            var jobs = await _db.SecurityScanJobs
                .AsNoTracking()
                .Where(job => job.CampaignId == attempt.CampaignId
                    && job.CampaignOccurrenceKey == attempt.OccurrenceKey)
                .OrderBy(job => job.Id)
                .Take(2)
                .ToListAsync(ct);

            if (jobs.Count != 1)
            {
                return null;
            }

            var job = jobs[0];
            var campaign = await _db.ScanCampaigns
                .AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == attempt.CampaignId
                    && candidate.TenantId == attempt.TenantId, ct);

            if (campaign == null)
            {
                return null;
            }

            var audits = await _db.CampaignExecutionAuditLogs
                .AsNoTracking()
                .Where(audit => audit.CampaignId == attempt.CampaignId
                    && audit.DispatchedScanJobId == job.Id
                    && (audit.Decision == SchedulerDecision.Dispatched
                        || audit.Decision == SchedulerDecision.QueuedNext))
                .OrderBy(audit => audit.Id)
                .Take(2)
                .ToListAsync(ct);

            if (audits.Count != 1)
            {
                return null;
            }

            var audit = audits[0];
            if (expectedDecision.HasValue && audit.Decision != expectedDecision.Value)
            {
                return null;
            }

            var expectedNextOccurrence = _calculator.CalculateNextOccurrence(
                attempt.ScheduleType,
                attempt.CronExpression,
                attempt.IntervalDuration,
                attempt.TimeZoneId,
                audit.EvaluatedAtUtc);
            var expectedNextRunUtc = expectedNextOccurrence.IsValid
                ? expectedNextOccurrence.NextOccurrenceUtc
                : null;

            var jobMatches = job.TenantId == attempt.TenantId
                && job.RepositoryId == attempt.RepositoryId
                && job.TargetId == attempt.SecurityTargetId
                && string.Equals(job.TargetUrl, attempt.TargetUrl, StringComparison.Ordinal)
                && job.ScanProfile == attempt.ScanProfile
                && job.RequestedByUserId == null
                && string.Equals(job.TriggeredBy, "CampaignScheduler", StringComparison.Ordinal)
                && SamePostgreSqlTimestamp(job.CreatedAtUtc, audit.EvaluatedAtUtc);

            var campaignMatches = campaign.ScheduleVersion == attempt.ExpectedScheduleVersion + 1
                && SamePostgreSqlTimestamp(campaign.NextRunUtc, expectedNextRunUtc)
                && string.Equals(
                    campaign.LastCampaignOccurrenceKey,
                    attempt.OccurrenceKey,
                    StringComparison.Ordinal)
                && campaign.LastScanJobId == job.Id
                && campaign.TotalRunsCount == attempt.ExpectedTotalRunsCount + 1
                && SamePostgreSqlTimestamp(campaign.LastRunUtc, audit.EvaluatedAtUtc)
                && SamePostgreSqlTimestamp(campaign.UpdatedAtUtc, audit.EvaluatedAtUtc);

            var auditMatches = audit.TenantId == attempt.TenantId
                && string.Equals(audit.TriggerSource, "CampaignScheduler", StringComparison.Ordinal)
                && audit.ScheduleVersion == attempt.ExpectedScheduleVersion + 1
                && AuditMetadataMatches(audit.MetadataJson, attempt);

            return jobMatches && campaignMatches && auditMatches
                ? audit.Decision
                : null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception reconciliationException)
        {
            _logger.LogWarning(
                reconciliationException,
                "CampaignScheduler: Failed to reconcile durable state for Campaign '{CampaignId}' occurrence '{OccurrenceKey}'.",
                attempt.CampaignId,
                attempt.OccurrenceKey);
            return null;
        }
    }

    private void DiscardPendingChanges()
    {
        foreach (var entry in _db.ChangeTracker.Entries()
                     .Where(entry => entry.State is EntityState.Added
                         or EntityState.Modified
                         or EntityState.Deleted)
                     .ToList())
        {
            entry.State = EntityState.Detached;
        }
    }

    private static bool AuditMetadataMatches(string? metadataJson, DispatchAttempt attempt)
    {
        if (string.IsNullOrWhiteSpace(metadataJson))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(metadataJson);
            var root = document.RootElement;
            return root.TryGetProperty("occurrenceKey", out var occurrenceKey)
                && string.Equals(
                    occurrenceKey.GetString(),
                    attempt.OccurrenceKey,
                    StringComparison.Ordinal)
                && root.TryGetProperty("scheduledOccurrenceUtc", out var scheduledOccurrence)
                && string.Equals(
                    scheduledOccurrence.GetString(),
                    attempt.ScheduledOccurrenceUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool SamePostgreSqlTimestamp(DateTime? left, DateTime? right)
    {
        if (!left.HasValue || !right.HasValue)
        {
            return left.HasValue == right.HasValue;
        }

        return TruncateToPostgreSqlMicroseconds(left.Value).Ticks
            == TruncateToPostgreSqlMicroseconds(right.Value).Ticks;
    }

    private static DateTime TruncateToPostgreSqlMicroseconds(DateTime value)
    {
        var ticks = value.Ticks - (value.Ticks % TimeSpan.TicksPerMicrosecond);
        return new DateTime(ticks, value.Kind);
    }

    private sealed record DispatchAttempt(
        Guid CampaignId,
        Guid TenantId,
        Guid RepositoryId,
        Guid SecurityTargetId,
        string TargetUrl,
        SecurityScanProfileType ScanProfile,
        ScheduleType ScheduleType,
        string? CronExpression,
        TimeSpan? IntervalDuration,
        string TimeZoneId,
        long ExpectedScheduleVersion,
        int ExpectedTotalRunsCount,
        DateTime ScheduledOccurrenceUtc,
        string OccurrenceKey);

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

            campaign.ScheduleVersion++;
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
    ///   SHA256("v1\n" + campaignId:D + "\n" + canonicalScheduledOccurrenceUtc:O + "\n" + scheduleVersion)
    ///
    /// Output: 64-character lowercase hexadecimal string.
    ///
    /// PostgreSQL timestamps have microsecond precision while DateTime has 100-nanosecond
    /// ticks. Quantizing UTC input to whole microseconds keeps keys stable before and after
    /// a database round trip without changing keys previously produced from persisted values.
    /// </summary>
    public static string ComputeOccurrenceKey(Guid campaignId, DateTime scheduledOccurrenceUtc, long scheduleVersion)
    {
        if (scheduledOccurrenceUtc.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("Scheduled occurrence must use DateTimeKind.Utc.", nameof(scheduledOccurrenceUtc));
        }

        var canonicalTicks = scheduledOccurrenceUtc.Ticks
            - (scheduledOccurrenceUtc.Ticks % TimeSpan.TicksPerMicrosecond);
        var canonicalOccurrenceUtc = new DateTime(canonicalTicks, DateTimeKind.Utc);
        var input = string.Concat(
            "v1\n",
            campaignId.ToString("D"),
            "\n",
            canonicalOccurrenceUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            "\n",
            scheduleVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
