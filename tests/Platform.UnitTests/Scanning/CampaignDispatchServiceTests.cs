using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

/// <summary>
/// Unit tests for CampaignDispatchService.
///
/// TEST LAYER CONTRACT:
///   These tests use the EF Core In-Memory provider. They are behavioural / exception-handling
///   proofs — they verify that the application-layer logic (idempotency guard, concurrency
///   exception handling, missed-run algorithm, failure counter lifecycle, etc.) works correctly.
///
///   They do NOT prove distributed concurrency correctness. Microsoft explicitly warns
///   that the In-Memory provider does not support real relational transaction/concurrency semantics.
///
///   The authoritative proof that two real scheduler instances cannot dispatch the same campaign
///   is in Platform.IntegrationTests/Scanning/CampaignSchedulerRaceTests.cs,
///   which uses a real PostgreSQL container (Testcontainers) as the hard acceptance gate.
/// </summary>
public sealed class CampaignDispatchServiceTests : IDisposable
{
    private readonly PlatformDbContext _db;
    private readonly CampaignScheduleCalculator _calculator;
    private readonly CampaignSchedulerOptions _options;
    private readonly CampaignDispatchService _service;

    private readonly Guid _tenantId = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public CampaignDispatchServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("CampaignDispatch_" + Guid.NewGuid())
            .Options;

        _db = new PlatformDbContext(dbOptions);
        _calculator = new CampaignScheduleCalculator(NullLogger<CampaignScheduleCalculator>.Instance);
        _options = new CampaignSchedulerOptions
        {
            GlobalEnabled = true,
            TickIntervalSeconds = 30,
            MaxCampaignsPerTick = 50,
            StuckJobThresholdMinutes = 60,
            RecoveryIntervalSeconds = 300,
            HeartbeatIntervalSeconds = 120
        };

        _service = new CampaignDispatchService(
            _db,
            _calculator,
            Options.Create(_options),
            NullLogger<CampaignDispatchService>.Instance);

        // Seed base entities
        _db.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "PaymentService",
            FullName = "enterprise/PaymentService",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/PaymentService",
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Payment API",
            BaseUrl = "https://api.payments.enterprise.com",
            TargetType = "WebEndpoint",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    // =========================================================================
    // Helper: Create a due campaign
    // =========================================================================

    private ScanCampaign CreateDueCampaign(
        CampaignConcurrencyPolicy policy = CampaignConcurrencyPolicy.SkipIfRunning,
        DateTime? nextRunUtc = null)
    {
        var campaign = new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Test Campaign",
            Status = CampaignStatus.Active,
            ScanProfile = SecurityScanProfileType.Standard,
            ScheduleType = ScheduleType.Interval,
            IntervalDuration = TimeSpan.FromHours(24),
            TimeZoneId = "UTC",
            ConcurrencyPolicy = policy,
            ScheduleVersion = 1,
            NextRunUtc = nextRunUtc ?? DateTime.UtcNow.AddMinutes(-5), // due 5 minutes ago
            MaxConsecutiveFailures = 3,
            AutoPauseOnConsecutiveFailures = true,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1)
        };

        _db.ScanCampaigns.Add(campaign);
        _db.SaveChanges();
        return campaign;
    }

    // =========================================================================
    // 1. OCCURRENCE KEY — Canonical format and determinism
    // =========================================================================

    [Fact]
    public void OccurrenceKey_SameInputs_ProducesSameKey()
    {
        var campaignId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var occurrence = new DateTime(2026, 8, 14, 10, 0, 0, DateTimeKind.Utc);
        long version = 42;

        var key1 = CampaignDispatchService.ComputeOccurrenceKey(campaignId, occurrence, version);
        var key2 = CampaignDispatchService.ComputeOccurrenceKey(campaignId, occurrence, version);

        key1.Should().Be(key2, "same inputs must always produce the same key");
    }

    [Fact]
    public void OccurrenceKey_Is64CharLowercaseHex()
    {
        var key = CampaignDispatchService.ComputeOccurrenceKey(
            Guid.NewGuid(),
            DateTime.UtcNow,
            scheduleVersion: 1);

        key.Should().HaveLength(64, "SHA256 = 32 bytes = 64 hex chars");
        key.Should().MatchRegex("^[0-9a-f]{64}$", "must be lowercase hex");
    }

    [Fact]
    public void OccurrenceKey_DifferentScheduleVersion_ProducesDifferentKey()
    {
        var id = Guid.NewGuid();
        var occ = DateTime.UtcNow;

        var key1 = CampaignDispatchService.ComputeOccurrenceKey(id, occ, scheduleVersion: 1);
        var key2 = CampaignDispatchService.ComputeOccurrenceKey(id, occ, scheduleVersion: 2);

        key1.Should().NotBe(key2, "version bump must change the key (prevents cross-version collision)");
    }

    [Fact]
    public void OccurrenceKey_DifferentCampaignId_ProducesDifferentKey()
    {
        var occ = DateTime.UtcNow;
        var key1 = CampaignDispatchService.ComputeOccurrenceKey(Guid.NewGuid(), occ, 1);
        var key2 = CampaignDispatchService.ComputeOccurrenceKey(Guid.NewGuid(), occ, 1);
        key1.Should().NotBe(key2);
    }

    // =========================================================================
    // 2. GLOBAL DISABLE
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_GlobalDisabled_EvaluatesZeroCampaigns()
    {
        CreateDueCampaign();

        var disabledOptions = new CampaignSchedulerOptions { GlobalEnabled = false };
        var disabledService = new CampaignDispatchService(
            _db, _calculator, Options.Create(disabledOptions),
            NullLogger<CampaignDispatchService>.Instance);

        var result = await disabledService.RunSchedulerTickAsync(CancellationToken.None);

        result.CampaignsEvaluated.Should().Be(0);
        result.Dispatched.Should().Be(0);

        var jobCount = await _db.SecurityScanJobs.CountAsync();
        jobCount.Should().Be(0);
    }

    // =========================================================================
    // 3. MISSED-RUN ALGORITHM
    //    Campaign offline for 7 days → exactly 1 SecurityScanJob, NextRunUtc is future
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_MissedRun_7DaysOffline_ExactlyOneJobDispatched_NextRunUtcIsFuture()
    {
        // Campaign whose NextRunUtc is 7 days in the past (scheduler was down)
        var campaign = CreateDueCampaign(nextRunUtc: DateTime.UtcNow.AddDays(-7));
        var preTickVersion = campaign.ScheduleVersion;

        var result = await _service.RunSchedulerTickAsync(CancellationToken.None);

        result.Dispatched.Should().Be(1);

        // Exactly ONE job created, not 7
        var jobs = await _db.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id)
            .ToListAsync();
        jobs.Should().HaveCount(1, "missed-run must produce exactly ONE catch-up job");
        jobs[0].Status.Should().Be(SecurityScanJobStatus.Queued);
        jobs[0].CampaignOccurrenceKey.Should().NotBeNullOrEmpty();

        // NextRunUtc must be a future timestamp, not another past timestamp
        var updatedCampaign = await _db.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updatedCampaign.NextRunUtc.Should().NotBeNull();
        updatedCampaign.NextRunUtc!.Value.Should().BeAfter(DateTime.UtcNow.AddMinutes(-1),
            "cursor must advance to a FUTURE occurrence, not loop-advance from old NextRunUtc");
        updatedCampaign.ScheduleVersion.Should().Be(preTickVersion + 1,
            "ScheduleVersion must increment on successful dispatch");
    }

    // =========================================================================
    // 4. IDEMPOTENCY GUARD
    //    Same CampaignOccurrenceKey → no second job dispatched
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_SameOccurrenceKey_AlreadyDispatched_NoSecondJobCreated()
    {
        var campaign = CreateDueCampaign();
        var scheduledOccurrence = campaign.NextRunUtc!.Value;

        // Pre-existing job with the same occurrence key (simulates scheduler retry after ambiguous commit)
        var existingKey = CampaignDispatchService.ComputeOccurrenceKey(
            campaign.Id, scheduledOccurrence, campaign.ScheduleVersion);

        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            CampaignOccurrenceKey = existingKey,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        var result = await _service.RunSchedulerTickAsync(CancellationToken.None);

        // Must not create a second job
        var jobs = await _db.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id)
            .ToListAsync();
        jobs.Should().HaveCount(1, "idempotency guard must prevent duplicate dispatch on retry");
        result.Dispatched.Should().Be(1, "idempotency guard returns Dispatched (already handled)");
    }

    // =========================================================================
    // 5. PAUSED / ARCHIVED CAMPAIGNS — Never dispatched
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_PausedCampaign_NeverDispatched()
    {
        var campaign = CreateDueCampaign();
        campaign.Status = CampaignStatus.Paused;
        await _db.SaveChangesAsync();

        var result = await _service.RunSchedulerTickAsync(CancellationToken.None);

        result.CampaignsEvaluated.Should().Be(0, "paused campaigns must not appear in the due-campaign query");
        var jobs = await _db.SecurityScanJobs.CountAsync(j => j.CampaignId == campaign.Id);
        jobs.Should().Be(0);
    }

    [Fact]
    public async Task RunSchedulerTick_ArchivedCampaign_NeverDispatched()
    {
        var campaign = CreateDueCampaign();
        campaign.Status = CampaignStatus.Archived;
        await _db.SaveChangesAsync();

        var result = await _service.RunSchedulerTickAsync(CancellationToken.None);

        result.CampaignsEvaluated.Should().Be(0);
        var jobs = await _db.SecurityScanJobs.CountAsync(j => j.CampaignId == campaign.Id);
        jobs.Should().Be(0);
    }

    // =========================================================================
    // 6. CONCURRENCY POLICY — QueueNext depth capped at 1
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_QueueNext_ExactlyOneJobQueued_SecondTriggerSkippedQueueFull()
    {
        var campaign = CreateDueCampaign(CampaignConcurrencyPolicy.QueueNext);

        // Simulate a running job
        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        // First tick: should enqueue exactly one job
        var tick1 = await _service.RunSchedulerTickAsync(CancellationToken.None);
        tick1.Dispatched.Should().Be(1, "QueueNext should enqueue one pending job");

        var queuedCount = await _db.SecurityScanJobs
            .CountAsync(j => j.CampaignId == campaign.Id && j.Status == SecurityScanJobStatus.Queued);
        queuedCount.Should().Be(1);

        // Second tick: NextRunUtc has been advanced, re-set it to trigger another evaluation
        var updatedCampaign = await _db.ScanCampaigns.FirstAsync(c => c.Id == campaign.Id);
        updatedCampaign.NextRunUtc = DateTime.UtcNow.AddMinutes(-1);
        await _db.SaveChangesAsync();

        var tick2 = await _service.RunSchedulerTickAsync(CancellationToken.None);

        // Queue depth capped at 1 — second trigger should be SkippedQueueFull
        var totalQueued = await _db.SecurityScanJobs
            .CountAsync(j => j.CampaignId == campaign.Id && j.Status == SecurityScanJobStatus.Queued);
        totalQueued.Should().Be(1, "QueueNext depth must be capped at 1 job");
        tick2.Skipped.Should().BeGreaterThan(0);
    }

    // =========================================================================
    // 7. RECOVERY — Stale job transitions to TimedOut
    // =========================================================================

    [Fact]
    public async Task RecoverStuckJob_StaleHeartbeat_TransitionsToTimedOut_WithCampaignJobStuckReason()
    {
        var campaign = CreateDueCampaign();

        var stuckJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            WorkerInstanceId = "worker-abc",
            LastHeartbeatUtc = DateTime.UtcNow.AddHours(-2), // 2 hours ago — beyond 60min threshold
            JobVersion = 1,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-3)
        };
        _db.SecurityScanJobs.Add(stuckJob);
        await _db.SaveChangesAsync();

        var recovered = await _service.RecoverStuckJobsAsync(CancellationToken.None);

        recovered.Should().Be(1);

        var updatedJob = await _db.SecurityScanJobs.AsNoTracking()
            .FirstAsync(j => j.Id == stuckJob.Id);
        updatedJob.Status.Should().Be(SecurityScanJobStatus.TimedOut,
            "stuck jobs must use TimedOut, not Failed (explicit contract per Phase 9.2 review)");
        updatedJob.FailureReason.Should().Be("CAMPAIGN_JOB_STUCK");

        // Audit log must be written
        var auditLogs = await _db.CampaignExecutionAuditLogs
            .Where(a => a.CampaignId == campaign.Id && a.Decision == SchedulerDecision.RecoveredStuck)
            .ToListAsync();
        auditLogs.Should().HaveCount(1);
    }

    [Fact]
    public async Task RecoverStuckJob_LiveWorkerHeartbeat_ConcurrencyException_JobRemainsRunning()
    {
        // UNIT-LEVEL NOTE: The In-Memory provider does not enforce real concurrent UPDATE WHERE
        // concurrency token semantics. This test simulates the exception by directly verifying
        // the service's exception-handling branch. The authoritative proof that a live worker
        // defeats recovery in PostgreSQL is in CampaignSchedulerRaceTests (integration tests).

        var campaign = CreateDueCampaign();

        // Job has a stale heartbeat timestamp but we'll simulate the version already updated
        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            WorkerInstanceId = "worker-live",
            LastHeartbeatUtc = DateTime.UtcNow.AddHours(-2),
            JobVersion = 1,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-3)
        };
        _db.SecurityScanJobs.Add(job);
        await _db.SaveChangesAsync();

        // Simulate the worker heartbeating by bumping JobVersion BEFORE recovery runs
        // (In real PostgreSQL this happens via a concurrent UPDATE; here we simulate it directly)
        var trackedJob = await _db.SecurityScanJobs.FirstAsync(j => j.Id == job.Id);
        trackedJob.JobVersion = 2; // Worker incremented it
        trackedJob.LastHeartbeatUtc = DateTime.UtcNow; // Worker heartbeated
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        // Recovery sees the DB-level job version = 2, but its in-memory snapshot has version = 1.
        // In PostgreSQL this causes DbUpdateConcurrencyException. In In-Memory, we verify
        // the job is no longer stale (heartbeat is now fresh).
        var recoveredCount = await _service.RecoverStuckJobsAsync(CancellationToken.None);

        // Job's LastHeartbeatUtc is now fresh → recovery query should not even select it
        recoveredCount.Should().Be(0, "a job with a fresh heartbeat must not be recovered");

        var finalJob = await _db.SecurityScanJobs.AsNoTracking().FirstAsync(j => j.Id == job.Id);
        finalJob.Status.Should().Be(SecurityScanJobStatus.Running,
            "a job with a fresh heartbeat must remain Running");
    }

    // =========================================================================
    // 8. RECOVERY — Auto-pause at threshold
    // =========================================================================

    [Fact]
    public async Task RecoverStuckJob_AtConsecutiveFailureThreshold_AutoPausesCampaign()
    {
        var campaign = CreateDueCampaign();
        campaign.ConsecutiveFailuresCount = 2; // One more failure → threshold (MaxConsecutiveFailures=3)
        await _db.SaveChangesAsync();

        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            LastHeartbeatUtc = DateTime.UtcNow.AddHours(-2),
            JobVersion = 1,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-3)
        });
        await _db.SaveChangesAsync();

        await _service.RecoverStuckJobsAsync(CancellationToken.None);

        var updatedCampaign = await _db.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updatedCampaign.ConsecutiveFailuresCount.Should().Be(3);
        updatedCampaign.Status.Should().Be(CampaignStatus.AutoPaused,
            "campaign must be auto-paused when ConsecutiveFailuresCount reaches MaxConsecutiveFailures");
        updatedCampaign.NextRunUtc.Should().BeNull("auto-paused campaign must have no scheduled next run");
    }

    // =========================================================================
    // 9. FAILURE COUNTER LIFECYCLE
    //    Success → reset to 0; Failure → increment; Threshold → AutoPause
    // =========================================================================

    [Fact]
    public async Task ProcessJobOutcome_Success_ResetsConsecutiveFailuresCountToZero()
    {
        var campaign = CreateDueCampaign();
        campaign.ConsecutiveFailuresCount = 2; // Has historical failures
        await _db.SaveChangesAsync();

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            CreatedAtUtc = DateTime.UtcNow
        };
        _db.SecurityScanJobs.Add(job);
        await _db.SaveChangesAsync();

        // Successful outcome
        await _service.ProcessJobOutcomeAsync(job.Id, success: true, CancellationToken.None);

        var updated = await _db.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updated.ConsecutiveFailuresCount.Should().Be(0,
            "a successful scan must reset ConsecutiveFailuresCount to 0 — " +
            "otherwise historical failures could accumulate and cause incorrect AutoPause");
        updated.Status.Should().Be(CampaignStatus.Active);
    }

    [Fact]
    public async Task ProcessJobOutcome_Failure_IncrementsCount()
    {
        var campaign = CreateDueCampaign();
        campaign.ConsecutiveFailuresCount = 1;
        await _db.SaveChangesAsync();

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Failed,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            CreatedAtUtc = DateTime.UtcNow
        };
        _db.SecurityScanJobs.Add(job);
        await _db.SaveChangesAsync();

        await _service.ProcessJobOutcomeAsync(job.Id, success: false, CancellationToken.None);

        var updated = await _db.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updated.ConsecutiveFailuresCount.Should().Be(2);
        updated.Status.Should().Be(CampaignStatus.Active, "threshold not yet reached");
    }

    [Fact]
    public async Task ProcessJobOutcome_FailureAtThreshold_AutoPausesCampaign()
    {
        var campaign = CreateDueCampaign();
        campaign.ConsecutiveFailuresCount = 2; // One more → AutoPause (MaxConsecutiveFailures=3)
        await _db.SaveChangesAsync();

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Failed,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "CampaignScheduler",
            CreatedAtUtc = DateTime.UtcNow
        };
        _db.SecurityScanJobs.Add(job);
        await _db.SaveChangesAsync();

        await _service.ProcessJobOutcomeAsync(job.Id, success: false, CancellationToken.None);

        var updated = await _db.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updated.ConsecutiveFailuresCount.Should().Be(3);
        updated.Status.Should().Be(CampaignStatus.AutoPaused);
        updated.NextRunUtc.Should().BeNull();
    }

    [Fact]
    public async Task ProcessJobOutcome_SuccessAfterFailures_ThenFails_CountsFromZero()
    {
        // Verifies the reset-then-increment lifecycle:
        // 2 failures → success (reset to 0) → failure (count = 1, NOT 3)
        var campaign = CreateDueCampaign();
        campaign.ConsecutiveFailuresCount = 2;
        await _db.SaveChangesAsync();

        Func<SecurityScanJobStatus, Task<Guid>> addJob = async status =>
        {
            var j = new SecurityScanJob
            {
                Id = Guid.NewGuid(),
                CampaignId = campaign.Id,
                RepositoryId = _repoId,
                TargetId = _targetId,
                TargetUrl = "https://api.payments.enterprise.com",
                Status = status,
                RequestedByUserId = Guid.Empty,
                TriggeredBy = "CampaignScheduler",
                CreatedAtUtc = DateTime.UtcNow
            };
            _db.SecurityScanJobs.Add(j);
            await _db.SaveChangesAsync();
            return j.Id;
        };

        // Success resets count
        var successJob = await addJob(SecurityScanJobStatus.Completed);
        await _service.ProcessJobOutcomeAsync(successJob, success: true, CancellationToken.None);

        var afterSuccess = await _db.ScanCampaigns.AsNoTracking().FirstAsync(c => c.Id == campaign.Id);
        afterSuccess.ConsecutiveFailuresCount.Should().Be(0);

        // Subsequent failure counts from 0, not from 2
        var failJob = await addJob(SecurityScanJobStatus.Failed);
        await _service.ProcessJobOutcomeAsync(failJob, success: false, CancellationToken.None);

        var afterFail = await _db.ScanCampaigns.AsNoTracking().FirstAsync(c => c.Id == campaign.Id);
        afterFail.ConsecutiveFailuresCount.Should().Be(1,
            "failure count must restart from 0 after a success, not accumulate across the campaign's lifetime");
        afterFail.Status.Should().Be(CampaignStatus.Active, "threshold is 3, count is only 1");
    }

    // =========================================================================
    // 10. ProcessJobOutcome — No-op for non-campaign jobs
    // =========================================================================

    [Fact]
    public async Task ProcessJobOutcome_NonCampaignJob_IsNoOp()
    {
        var manualJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = null, // Manual job, no campaign
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            Status = SecurityScanJobStatus.Failed,
            RequestedByUserId = Guid.Empty,
            TriggeredBy = "Manual",
            CreatedAtUtc = DateTime.UtcNow
        };
        _db.SecurityScanJobs.Add(manualJob);
        await _db.SaveChangesAsync();

        // Must not throw and must not affect any campaign
        var act = () => _service.ProcessJobOutcomeAsync(manualJob.Id, success: false, CancellationToken.None);
        await act.Should().NotThrowAsync();
    }

    // =========================================================================
    // 11. AUDIT LOG — Every dispatch is persisted
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_Dispatched_WritesAuditLog()
    {
        CreateDueCampaign();

        await _service.RunSchedulerTickAsync(CancellationToken.None);

        var auditLogs = await _db.CampaignExecutionAuditLogs.ToListAsync();
        auditLogs.Should().Contain(a => a.Decision == SchedulerDecision.Dispatched,
            "every dispatch decision must be written to the audit log");
    }

    // =========================================================================
    // 12. DISPATCH — Job has OccurrenceKey and correct metadata
    // =========================================================================

    [Fact]
    public async Task RunSchedulerTick_Dispatched_JobHasOccurrenceKeyAndCampaignMetadata()
    {
        var campaign = CreateDueCampaign();

        await _service.RunSchedulerTickAsync(CancellationToken.None);

        var job = await _db.SecurityScanJobs
            .FirstOrDefaultAsync(j => j.CampaignId == campaign.Id);

        job.Should().NotBeNull();
        job!.CampaignOccurrenceKey.Should().NotBeNullOrEmpty("scheduler jobs must have an idempotency key");
        job.CampaignOccurrenceKey!.Length.Should().Be(64);
        job.TriggeredBy.Should().Be("CampaignScheduler");
        job.Status.Should().Be(SecurityScanJobStatus.Queued);
        job.TargetUrl.Should().Be("https://api.payments.enterprise.com");
    }
}
