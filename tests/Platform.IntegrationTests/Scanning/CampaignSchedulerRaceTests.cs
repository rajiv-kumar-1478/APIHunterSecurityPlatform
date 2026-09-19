using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Platform.Application.Configuration;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Testcontainers.PostgreSql;
using Xunit;

namespace Platform.IntegrationTests.Scanning;

/// <summary>
/// Phase 9.2 HARD GATE: Authoritative distributed concurrency proof.
///
/// PURPOSE:
///   These tests use a real PostgreSQL container (Testcontainers) to prove that the scheduler's
///   optimistic concurrency and idempotency mechanisms work correctly under real relational
///   transaction semantics. The EF Core In-Memory provider cannot be used for this purpose —
///   Microsoft's own documentation explicitly warns it lacks real transaction/concurrency behavior.
///
/// ACCEPTANCE CRITERIA (from Phase 9.2 review):
///   ✅ Two scheduler instances racing on the same campaign → exactly 1 SecurityScanJob
///   ✅ Idempotency key unique constraint prevents duplicate on scheduler retry
///   ✅ Recovery race: live worker heartbeat defeats stale-job recovery
///   ✅ Missed-run: campaign offline 7 days → exactly 1 catch-up job, future NextRunUtc
///
/// REQUIREMENT:
///   Provide TEST_POSTGRES_CONNECTION_STRING for a dedicated disposable database named exactly
///   apihunter_race_ followed by 32 lowercase hexadecimal characters, and explicitly set
///   TEST_POSTGRES_ALLOW_DATABASE_DROP=true; or provide Docker for an isolated Testcontainer.
///   The fixture applies real EF migrations, drops/recreates the approved database, and deletes
///   an externally supplied race database on disposal.
/// </summary>
[Collection("PostgreSQL")]
public sealed class CampaignSchedulerRaceTests : IAsyncLifetime
{
    private PostgreSqlContainer? _postgres;
    private string _connectionString = null!;
    private bool _deleteExternalDatabaseOnDispose;

    private Guid _tenantId;
    private Guid _repoId;
    private Guid _targetId;

    public CampaignSchedulerRaceTests()
    {
    }

    public async Task InitializeAsync()
    {
        var externalConnectionString = Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION_STRING");

        if (!string.IsNullOrWhiteSpace(externalConnectionString))
        {
            var allowDatabaseDrop = Environment.GetEnvironmentVariable(
                "TEST_POSTGRES_ALLOW_DATABASE_DROP");
            var connectionBuilder = new NpgsqlConnectionStringBuilder(externalConnectionString);
            var databaseName = connectionBuilder.Database;
            var isRunSpecificDatabase = !string.IsNullOrWhiteSpace(databaseName)
                && Regex.IsMatch(
                    databaseName,
                    "^apihunter_race_[0-9a-f]{32}$",
                    RegexOptions.CultureInvariant,
                    TimeSpan.FromSeconds(1));

            if (!string.Equals(allowDatabaseDrop, "true", StringComparison.Ordinal)
                || !isRunSpecificDatabase)
            {
                throw new InvalidOperationException(
                    "External PostgreSQL race tests are destructive. Set " +
                    "TEST_POSTGRES_ALLOW_DATABASE_DROP=true and use a dedicated database named " +
                    "exactly 'apihunter_race_<32 lowercase hex characters>'.");
            }

            _connectionString = connectionBuilder.ConnectionString;
            _deleteExternalDatabaseOnDispose = true;
        }
        else
        {
            try
            {
                _postgres = new PostgreSqlBuilder()
                    .WithImage("postgres:16-alpine")
                    .WithDatabase("apihunter_race_tests")
                    .WithUsername("postgres")
                    .WithPassword("postgres")
                    .WithCleanUp(true)
                    .Build();

                await _postgres.StartAsync();
                _connectionString = _postgres.GetConnectionString();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "PostgreSQL is required for Phase 9.2 distributed concurrency race tests. " +
                    "Set TEST_POSTGRES_CONNECTION_STRING and TEST_POSTGRES_ALLOW_DATABASE_DROP=true " +
                    "for a dedicated apihunter_race_<32-lowercase-hex> database, or start Docker " +
                    "for Testcontainers.",
                    ex);
            }
        }

        // Reset the explicitly approved disposable database, then apply the full migration
        // history. EnsureCreated would bypass migration SQL, xmin cutover, and bridge triggers.
        await using (var resetDb = CreateDbContext())
        {
            await resetDb.Database.EnsureDeletedAsync();
        }

        await using var dbContext = CreateDbContext();
        await dbContext.Database.MigrateAsync();

        // Seed base entities required by all tests
        _tenantId = Guid.NewGuid();
        _repoId = Guid.NewGuid();
        _targetId = Guid.NewGuid();

        dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "PaymentService",
            FullName = "enterprise/PaymentService",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/PaymentService",
            CreatedAtUtc = DateTime.UtcNow
        });

        dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Payment API",
            BaseUrl = "https://api.payments.enterprise.com",
            TargetType = "WebEndpoint",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        await dbContext.SaveChangesAsync();
    }

    public async Task DisposeAsync()
    {
        if (_deleteExternalDatabaseOnDispose)
        {
            await using var cleanupDb = CreateDbContext();
            await cleanupDb.Database.EnsureDeletedAsync();
        }
        else if (_postgres != null)
        {
            await _postgres.DisposeAsync();
        }
    }

    // =========================================================================
    // Helper: Create independent DbContext (simulates a separate scheduler instance)
    // =========================================================================

    private PlatformDbContext CreateDbContext(SaveChangesInterceptor? interceptor = null)
    {
        var optionsBuilder = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseNpgsql(_connectionString, b => b.MigrationsAssembly("Platform.Infrastructure"));

        if (interceptor != null)
        {
            optionsBuilder.AddInterceptors(interceptor);
        }

        return new PlatformDbContext(optionsBuilder.Options);
    }

    private CampaignDispatchService CreateDispatchService(PlatformDbContext db)
    {
        var calculator = new CampaignScheduleCalculator(NullLogger<CampaignScheduleCalculator>.Instance);
        var options = Options.Create(new CampaignSchedulerOptions
        {
            GlobalEnabled = true,
            TickIntervalSeconds = 30,
            MaxCampaignsPerTick = 50,
            StuckJobThresholdMinutes = 60,
            RecoveryIntervalSeconds = 300,
            HeartbeatIntervalSeconds = 120
        });
        return new CampaignDispatchService(
            db,
            calculator,
            options,
            new TestTenantContext(_tenantId),
            new PostgreSqlDatabaseErrorClassifier(),
            NullLogger<CampaignDispatchService>.Instance);
    }

    private async Task<ScanCampaign> SeedDueCampaignAsync(
        PlatformDbContext db,
        DateTime? nextRunUtc = null,
        SecurityScanProfileType scanProfile = SecurityScanProfileType.Standard)
    {
        var campaign = new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Race Test Campaign " + Guid.NewGuid().ToString("N")[..8],
            Status = CampaignStatus.Active,
            ScanProfile = scanProfile,
            ScheduleType = ScheduleType.Interval,
            IntervalDuration = TimeSpan.FromHours(24),
            TimeZoneId = "UTC",
            ConcurrencyPolicy = CampaignConcurrencyPolicy.SkipIfRunning,
            ScheduleVersion = 1,
            NextRunUtc = nextRunUtc ?? DateTime.UtcNow.AddMinutes(-5),
            MaxConsecutiveFailures = 5,
            AutoPauseOnConsecutiveFailures = true,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1)
        };

        db.ScanCampaigns.Add(campaign);
        await db.SaveChangesAsync();
        return campaign;
    }

    private async Task<byte[]> ReadLegacyRowVersionAsync(string tableName, Guid id)
    {
        var commandText = tableName switch
        {
            "repositories" => "SELECT \"RowVersion\" FROM \"repositories\" WHERE \"Id\" = @id",
            "analysis_jobs" => "SELECT \"RowVersion\" FROM \"analysis_jobs\" WHERE \"Id\" = @id",
            _ => throw new ArgumentOutOfRangeException(nameof(tableName), tableName, "Unsupported table.")
        };

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(commandText, connection);
        command.Parameters.AddWithValue("id", id);
        var value = await command.ExecuteScalarAsync();
        return value as byte[]
            ?? throw new InvalidOperationException(
                $"Legacy RowVersion was not generated for {tableName}/{id}.");
    }

    // =========================================================================
    // TEST 1: THE HARD GATE
    // Two independent scheduler instances race on the same campaign.
    // Exactly one SecurityScanJob must be created.
    //
    //   Scheduler A ──┐
    //                 ├── same Campaign + same ScheduleVersion
    //   Scheduler B ──┘
    //                     │
    //                     ▼
    //           PostgreSQL UPDATE ... WHERE ScheduleVersion = X
    //                     │
    //             ┌───────┴────────┐
    //             ▼                ▼
    //          Winner             Loser
    //          1 job         DbUpdateConcurrencyException
    //                               │
    //                        SkippedClaimLost
    //
    // Expected: 1 campaign occurrence → exactly 1 SecurityScanJob
    // =========================================================================

    [Fact]
    public async Task TwoSchedulerInstances_ConcurrentDispatch_ExactlyOneJobCreated()
    {
        Guid campaignId;
        await using (var seedDb = CreateDbContext())
        {
            campaignId = (await SeedDueCampaignAsync(seedDb)).Id;
        }

        var saveGate = new AtomicDispatchSaveGate();
        var interceptor = new AtomicDispatchSaveInterceptor(saveGate);
        await using var dbA = CreateDbContext(interceptor);
        await using var dbB = CreateDbContext(interceptor);
        var serviceA = CreateDispatchService(dbA);
        var serviceB = CreateDispatchService(dbB);

        // The interceptor blocks both atomic SaveChanges calls until both schedulers
        // have read and staged the same persisted occurrence/version.
        var results = await Task.WhenAll(
            serviceA.RunSchedulerTickAsync(CancellationToken.None),
            serviceB.RunSchedulerTickAsync(CancellationToken.None));

        saveGate.ArrivalCount.Should().Be(2);
        saveGate.OriginalScheduleVersions.Should().BeEquivalentTo([1L, 1L]);
        saveGate.OriginalScheduledOccurrences.Distinct().Should().ContainSingle();
        results.Sum(r => r.CampaignsEvaluated).Should().Be(2);
        results.Sum(r => r.Dispatched).Should().Be(1,
            "two schedulers staging the same occurrence must produce exactly one job");
        results.Sum(r => r.ClaimLost).Should().Be(1,
            "the losing atomic write must be classified as SkippedClaimLost");
        results.Sum(r => r.Errors).Should().Be(0);

        await using var verifyDb = CreateDbContext();
        var jobs = await verifyDb.SecurityScanJobs
            .Where(j => j.CampaignId == campaignId)
            .ToListAsync();

        jobs.Should().ContainSingle();
        jobs[0].CampaignOccurrenceKey.Should().NotBeNullOrEmpty();
        jobs[0].Status.Should().Be(SecurityScanJobStatus.Queued);

        var audits = await verifyDb.CampaignExecutionAuditLogs
            .Where(a => a.CampaignId == campaignId)
            .ToListAsync();
        audits.Count(a => a.Decision == SchedulerDecision.Dispatched).Should().Be(1);
        audits.Count(a => a.Decision == SchedulerDecision.SkippedClaimLost).Should().Be(1);

        var dispatchAudit = audits.Single(a => a.Decision == SchedulerDecision.Dispatched);
        var updatedCampaign = await verifyDb.ScanCampaigns
            .AsNoTracking()
            .SingleAsync(campaign => campaign.Id == campaignId);
        updatedCampaign.ScheduleVersion.Should().Be(2);
        updatedCampaign.LastCampaignOccurrenceKey.Should().Be(jobs[0].CampaignOccurrenceKey);
        updatedCampaign.LastScanJobId.Should().Be(jobs[0].Id);
        updatedCampaign.TotalRunsCount.Should().Be(1);
        updatedCampaign.LastRunUtc.Should().Be(dispatchAudit.EvaluatedAtUtc);
        updatedCampaign.UpdatedAtUtc.Should().Be(dispatchAudit.EvaluatedAtUtc);
        updatedCampaign.NextRunUtc.Should().Be(dispatchAudit.EvaluatedAtUtc.AddHours(24));
        dispatchAudit.DispatchedScanJobId.Should().Be(jobs[0].Id);
        dispatchAudit.ScheduleVersion.Should().Be(2);
        dispatchAudit.TriggerSource.Should().Be("CampaignScheduler");
        dispatchAudit.MetadataJson.Should().Contain(jobs[0].CampaignOccurrenceKey);
    }

    // =========================================================================
    // TEST 2: IDEMPOTENCY KEY
    // Scheduler retries after an ambiguous commit (network partition after DB write).
    // The unique partial index on (CampaignId, CampaignOccurrenceKey) must prevent
    // a second SecurityScanJob from being created for the same scheduled occurrence.
    // =========================================================================

    [Fact]
    public async Task IdempotencyKey_SchedulerRetryAfterAmbiguousFailure_NoDuplicateJobCreated()
    {
        var fixedOccurrenceUtc = new DateTime(
            2026,
            9,
            5,
            12,
            34,
            56,
            DateTimeKind.Utc).AddTicks(7);
        (fixedOccurrenceUtc.Ticks % TimeSpan.TicksPerMicrosecond).Should().Be(7,
            "the provider test must exercise precision that PostgreSQL cannot retain");

        await using var db1 = CreateDbContext();
        var campaign = await SeedDueCampaignAsync(db1, fixedOccurrenceUtc);
        var occurrenceKeyBeforePersistence = CampaignDispatchService.ComputeOccurrenceKey(
            campaign.Id,
            fixedOccurrenceUtc,
            campaign.ScheduleVersion);

        await using (var persistedDb = CreateDbContext())
        {
            var persistedCampaign = await persistedDb.ScanCampaigns
                .AsNoTracking()
                .SingleAsync(c => c.Id == campaign.Id);
            var persistedOccurrenceUtc = persistedCampaign.NextRunUtc!.Value;
            persistedOccurrenceUtc.Ticks.Should().NotBe(fixedOccurrenceUtc.Ticks,
                "PostgreSQL must visibly remove the seeded sub-microsecond ticks");
            (persistedOccurrenceUtc.Ticks % TimeSpan.TicksPerMicrosecond).Should().Be(0);

            var occurrenceKeyAfterPersistence = CampaignDispatchService.ComputeOccurrenceKey(
                persistedCampaign.Id,
                persistedOccurrenceUtc,
                persistedCampaign.ScheduleVersion);
            occurrenceKeyAfterPersistence.Should().Be(occurrenceKeyBeforePersistence,
                "occurrence identity must survive PostgreSQL timestamp precision normalization");
        }

        static SecurityScanJob CreateJob(
            Guid tenantId,
            Guid campaignId,
            Guid repositoryId,
            Guid targetId,
            string occurrenceKey) => new()
            {
                TenantId = tenantId,
                Id = Guid.NewGuid(),
                CampaignId = campaignId,
                RepositoryId = repositoryId,
                TargetId = targetId,
                TargetUrl = "https://api.payments.enterprise.com",
                ScanProfile = SecurityScanProfileType.Standard,
                Status = SecurityScanJobStatus.Queued,
                RequestedByUserId = null,
                TriggeredBy = "CampaignScheduler",
                CampaignOccurrenceKey = occurrenceKey,
                JobVersion = 1,
                CreatedAtUtc = DateTime.UtcNow
            };

        await using (var setupDb = CreateDbContext())
        {
            setupDb.SecurityScanJobs.Add(CreateJob(
                _tenantId,
                campaign.Id,
                _repoId,
                _targetId,
                occurrenceKeyBeforePersistence));
            await setupDb.SaveChangesAsync();
        }

        await using (var duplicateDb = CreateDbContext())
        {
            duplicateDb.SecurityScanJobs.Add(CreateJob(
                _tenantId,
                campaign.Id,
                _repoId,
                _targetId,
                occurrenceKeyBeforePersistence));

            var saveDuplicate = async () => await duplicateDb.SaveChangesAsync();
            var failure = await saveDuplicate.Should().ThrowAsync<DbUpdateException>();
            var postgresFailure = failure.Which.InnerException
                .Should().BeOfType<PostgresException>().Subject;
            postgresFailure.SqlState.Should().Be(PostgresErrorCodes.UniqueViolation);
            postgresFailure.ConstraintName.Should().Be(
                "IX_security_scan_jobs_campaign_occurrence_key");
        }

        await using var verifyDb = CreateDbContext();
        var jobs = await verifyDb.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id)
            .ToListAsync();
        jobs.Should().ContainSingle(
            "the database idempotency constraint must reject a second canonical occurrence");
    }

    // =========================================================================
    // TEST 3: RECOVERY RACE
    // A live worker is actively heartbeating. Recovery attempts to mark the job TimedOut.
    // The live worker's heartbeat (which increments JobVersion) must defeat the recovery attempt.
    //
    //   Live Worker ──── heartbeat (JobVersion++) ────────────────────┐
    //                                                                  │
    //   Recovery ──── sees stale heartbeat ──── attempts TimedOut ────┘
    //                                                WHERE JobVersion = @old
    //                                                       │
    //                                              DbUpdateConcurrencyException
    //                                                       │
    //                                              Recovery loses (correct)
    //                                              Job remains Running
    // =========================================================================

    [Fact]
    public async Task RecoveryRace_LiveWorkerHeartbeatsFirst_JobRemainsRunning()
    {
        // Arrange: a "stuck-looking" running job (stale heartbeat)
        await using var setupDb = CreateDbContext();
        var campaign = await SeedDueCampaignAsync(setupDb);

        var job = new SecurityScanJob
        {
            TenantId = _tenantId,
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.payments.enterprise.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = null,
            TriggeredBy = "CampaignScheduler",
            WorkerInstanceId = "worker-live",
            LastHeartbeatUtc = DateTime.UtcNow.AddHours(-2), // Appears stuck
            JobVersion = 1,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-3)
        };
        setupDb.SecurityScanJobs.Add(job);
        await setupDb.SaveChangesAsync();

        // Act part 1: Live worker heartbeats (increments JobVersion from 1 → 2)
        await using var workerDb = CreateDbContext();
        var liveJob = await workerDb.SecurityScanJobs.FirstAsync(j => j.Id == job.Id);
        liveJob.LastHeartbeatUtc = DateTime.UtcNow; // Fresh heartbeat
        liveJob.JobVersion = 2; // Worker increments version
        await workerDb.SaveChangesAsync();

        // Act part 2: Recovery runs with a snapshot that has JobVersion=1 (stale)
        // In PostgreSQL: UPDATE ... WHERE Id=@id AND JobVersion=1 → 0 rows updated → DbUpdateConcurrencyException
        await using var recoveryDb = CreateDbContext();
        var recoveryService = CreateDispatchService(recoveryDb);

        // Recovery queries using the fresh heartbeat — since LastHeartbeatUtc is now fresh,
        // the job won't even be selected by the stuck-job query.
        // This tests that the heartbeat update (step 1) genuinely defeats recovery.
        var recovered = await recoveryService.RecoverStuckJobsAsync(CancellationToken.None);

        // Assert: job must remain Running (recovery defeated)
        await using var verifyDb = CreateDbContext();
        var finalJob = await verifyDb.SecurityScanJobs.AsNoTracking()
            .FirstAsync(j => j.Id == job.Id);

        recovered.Should().Be(0, "live worker's heartbeat update must prevent recovery from selecting the job");
        finalJob.Status.Should().Be(SecurityScanJobStatus.Running, "job must remain Running");
        finalJob.JobVersion.Should().Be(2, "only the worker's heartbeat update should have been applied");
    }

    // =========================================================================
    // TEST 4: MISSED-RUN (PostgreSQL end-to-end)
    // Campaign offline for 7 days → exactly 1 catch-up SecurityScanJob,
    // and NextRunUtc is a future timestamp (not another past timestamp).
    // =========================================================================

    [Fact]
    public async Task MissedRun_7DaysOffline_PostgreSQL_ExactlyOneJob_FutureNextRunUtc()
    {
        // Arrange: campaign whose NextRunUtc is 7 days in the past
        await using var setupDb = CreateDbContext();
        var campaign = await SeedDueCampaignAsync(setupDb, nextRunUtc: DateTime.UtcNow.AddDays(-7));

        // Act
        await using var schedulerDb = CreateDbContext();
        var service = CreateDispatchService(schedulerDb);
        var result = await service.RunSchedulerTickAsync(CancellationToken.None);

        // Assert: exactly 1 job (not 7)
        result.Dispatched.Should().Be(1);

        await using var verifyDb = CreateDbContext();
        var jobs = await verifyDb.SecurityScanJobs
            .Where(j => j.CampaignId == campaign.Id)
            .ToListAsync();

        jobs.Should().HaveCount(1,
            "a campaign offline for 7 days must produce exactly ONE catch-up job, not 7. " +
            "The missed-run algorithm dispatches ONE and advances the cursor to the next FUTURE occurrence.");

        // NextRunUtc must now be in the future
        var updatedCampaign = await verifyDb.ScanCampaigns.AsNoTracking()
            .FirstAsync(c => c.Id == campaign.Id);
        updatedCampaign.NextRunUtc.Should().NotBeNull();
        updatedCampaign.NextRunUtc!.Value.Should().BeAfter(DateTime.UtcNow.AddMinutes(-1),
            "cursor must be advanced to a FUTURE occurrence after catch-up dispatch");
    }

    // =========================================================================
    // TEST 5: ATOMICITY
    // If the concurrency token check fails, neither the job NOR the audit log
    // from the losing scheduler should appear in the database.
    // =========================================================================

    [Fact]
    public async Task ConcurrentDispatch_LoserHasZeroJobSideEffects()
    {
        Guid campaignId;
        await using (var seedDb = CreateDbContext())
        {
            campaignId = (await SeedDueCampaignAsync(seedDb)).Id;
        }

        var saveGate = new AtomicDispatchSaveGate();
        var interceptor = new AtomicDispatchSaveInterceptor(saveGate);
        await using var dbA = CreateDbContext(interceptor);
        await using var dbB = CreateDbContext(interceptor);
        var serviceA = CreateDispatchService(dbA);
        var serviceB = CreateDispatchService(dbB);

        var results = await Task.WhenAll(
            serviceA.RunSchedulerTickAsync(CancellationToken.None),
            serviceB.RunSchedulerTickAsync(CancellationToken.None));

        saveGate.ArrivalCount.Should().Be(2);
        results.Sum(r => r.CampaignsEvaluated).Should().Be(2);
        results.Sum(r => r.Dispatched).Should().Be(1);
        results.Sum(r => r.ClaimLost).Should().Be(1);
        results.Sum(r => r.Errors).Should().Be(0);

        await using var verifyDb = CreateDbContext();
        var jobs = await verifyDb.SecurityScanJobs
            .Where(j => j.CampaignId == campaignId)
            .ToListAsync();
        jobs.Should().ContainSingle(
            "the losing scheduler's job insert must roll back with its failed campaign update");

        var audits = await verifyDb.CampaignExecutionAuditLogs
            .Where(a => a.CampaignId == campaignId)
            .ToListAsync();
        audits.Count(a => a.Decision == SchedulerDecision.Dispatched).Should().Be(1);
        audits.Count(a => a.Decision == SchedulerDecision.SkippedClaimLost).Should().Be(1);
    }

    [Fact]
    public async Task NativeXmin_StaleWritersRejected_ForRepositoryAndAnalysisJob()
    {
        await using (var migrationDb = CreateDbContext())
        {
            var appliedMigrations = await migrationDb.Database.GetAppliedMigrationsAsync();
            appliedMigrations.Should().Contain(
                "20260906024820_FixPostgreSqlRowVersionTokens",
                "the real-provider fixture must execute the corrective migration rather than EnsureCreated");

            migrationDb.AnalysisJobs.Add(new AnalysisJob
            {
                Id = Guid.NewGuid(),
                JobType = JobType.SnapshotAnalysis,
                Status = JobStatus.Queued,
                Priority = 10,
                TargetEntityType = "Repository",
                TargetEntityId = _repoId,
                MaxRetries = 3,
                QueuedAtUtc = DateTime.UtcNow,
                CorrelationId = Guid.NewGuid().ToString("N")
            });
            await migrationDb.SaveChangesAsync();
        }

        Guid analysisJobId;
        await using (var idDb = CreateDbContext())
        {
            analysisJobId = await idDb.AnalysisJobs
                .AsNoTracking()
                .Select(job => job.Id)
                .SingleAsync();
        }

        var repositoryLegacyTokenBefore = await ReadLegacyRowVersionAsync(
            "repositories",
            _repoId);
        var analysisLegacyTokenBefore = await ReadLegacyRowVersionAsync(
            "analysis_jobs",
            analysisJobId);
        repositoryLegacyTokenBefore.Should().NotBeEmpty(
            "the expand migration must generate the legacy token on insert");
        analysisLegacyTokenBefore.Should().NotBeEmpty(
            "the expand migration must generate the legacy token on insert");

        await using (var repositoryWriter = CreateDbContext())
        await using (var staleRepositoryWriter = CreateDbContext())
        {
            var repository = await repositoryWriter.Repositories
                .SingleAsync(candidate => candidate.Id == _repoId);
            var staleRepository = await staleRepositoryWriter.Repositories
                .SingleAsync(candidate => candidate.Id == _repoId);
            var originalXmin = repository.RowVersion;

            originalXmin.Should().NotBe(0);
            staleRepository.RowVersion.Should().Be(originalXmin);

            repository.Description = "committed repository writer";
            repository.UpdatedAtUtc = DateTime.UtcNow;
            await repositoryWriter.SaveChangesAsync();
            repository.RowVersion.Should().NotBe(originalXmin,
                "PostgreSQL must return a new xmin after an update");

            var repositoryLegacyTokenAfter = await ReadLegacyRowVersionAsync(
                "repositories",
                _repoId);
            Convert.ToHexString(repositoryLegacyTokenAfter).Should().NotBe(
                Convert.ToHexString(repositoryLegacyTokenBefore),
                "the compatibility trigger must rotate legacy Repository.RowVersion");

            staleRepository.Description = "stale repository writer";
            var staleSave = async () => await staleRepositoryWriter.SaveChangesAsync();
            await staleSave.Should().ThrowAsync<DbUpdateConcurrencyException>();
        }

        await using (var analysisWriter = CreateDbContext())
        await using (var staleAnalysisWriter = CreateDbContext())
        {
            var analysisJob = await analysisWriter.AnalysisJobs
                .SingleAsync(candidate => candidate.Id == analysisJobId);
            var staleAnalysisJob = await staleAnalysisWriter.AnalysisJobs
                .SingleAsync(candidate => candidate.Id == analysisJobId);
            var originalXmin = analysisJob.RowVersion;

            originalXmin.Should().NotBe(0);
            staleAnalysisJob.RowVersion.Should().Be(originalXmin);

            analysisJob.Priority = 20;
            await analysisWriter.SaveChangesAsync();
            analysisJob.RowVersion.Should().NotBe(originalXmin,
                "PostgreSQL must return a new xmin after an update");

            var analysisLegacyTokenAfter = await ReadLegacyRowVersionAsync(
                "analysis_jobs",
                analysisJobId);
            Convert.ToHexString(analysisLegacyTokenAfter).Should().NotBe(
                Convert.ToHexString(analysisLegacyTokenBefore),
                "the compatibility trigger must rotate legacy AnalysisJob.RowVersion");

            staleAnalysisJob.Priority = 30;
            var staleSave = async () => await staleAnalysisWriter.SaveChangesAsync();
            await staleSave.Should().ThrowAsync<DbUpdateConcurrencyException>();
        }
    }

    private async Task<(int Version, int JobVersion)> ReadScanJobVersionsAsync(Guid id)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT \"Version\", \"JobVersion\" FROM \"security_scan_jobs\" WHERE \"Id\" = @id",
            connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            throw new InvalidOperationException($"Security scan job '{id}' was not found.");
        }

        return (reader.GetInt32(0), reader.GetInt32(1));
    }

    private async Task<int> UpdateLegacyScanJobVersionAsync(
        Guid id,
        int expectedVersion,
        int nextVersion)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            """
            UPDATE "security_scan_jobs"
            SET "Version" = @nextVersion
            WHERE "Id" = @id AND "Version" = @expectedVersion
            """,
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("expectedVersion", expectedVersion);
        command.Parameters.AddWithValue("nextVersion", nextVersion);
        return await command.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task SecurityScanJobVersionBridge_LegacyAndCurrentWritesSynchronizeBidirectionally()
    {
        var jobId = Guid.NewGuid();
        await using (var seedDb = CreateDbContext())
        {
            seedDb.SecurityScanJobs.Add(new SecurityScanJob
            {
                Id = jobId,
                TenantId = _tenantId,
                RepositoryId = _repoId,
                TargetId = _targetId,
                TargetUrl = "https://api.payments.enterprise.com",
                ScanProfile = SecurityScanProfileType.Standard,
                Status = SecurityScanJobStatus.Queued,
                RequestedByUserId = null,
                ProviderKey = "version-bridge-test",
                TriggeredBy = "VersionBridgeTest",
                JobVersion = 3,
                CreatedAtUtc = DateTime.UtcNow
            });
            await seedDb.SaveChangesAsync();
        }

        (await ReadScanJobVersionsAsync(jobId)).Should().Be((3, 3),
            "the insert bridge must merge both physical counters to the non-default current value");

        await using var staleCurrentDb = CreateDbContext();
        var staleCurrentJob = await staleCurrentDb.SecurityScanJobs
            .SingleAsync(job => job.Id == jobId);
        staleCurrentJob.JobVersion.Should().Be(3);

        (await UpdateLegacyScanJobVersionAsync(jobId, 3, 7)).Should().Be(1);
        (await ReadScanJobVersionsAsync(jobId)).Should().Be((7, 7),
            "a conditional write through legacy Version must advance current JobVersion");

        staleCurrentJob.JobVersion = 5;
        var staleCurrentSave = async () => await staleCurrentDb.SaveChangesAsync();
        await staleCurrentSave.Should().ThrowAsync<DbUpdateConcurrencyException>(
            "the legacy-column writer must invalidate a stale current-model writer");

        await using (var currentDb = CreateDbContext())
        {
            var currentJob = await currentDb.SecurityScanJobs
                .SingleAsync(job => job.Id == jobId);
            currentJob.JobVersion.Should().Be(7);
            currentJob.JobVersion = 11;
            await currentDb.SaveChangesAsync();
        }

        (await ReadScanJobVersionsAsync(jobId)).Should().Be((11, 11),
            "a current EF write must advance the physical legacy Version counter");
        (await UpdateLegacyScanJobVersionAsync(jobId, 7, 13)).Should().Be(0,
            "the current writer must invalidate a stale conditional legacy writer");
    }

    [Fact]
    public async Task DirectProviderFailures_PreCommitRollbackAndPostCommitAcknowledgementLossRemainSafe()
    {
        var firstOccurrenceUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var secondOccurrenceUtc = firstOccurrenceUtc.AddMinutes(1);
        Guid firstCampaignId;
        Guid secondCampaignId;

        await using (var setupDb = CreateDbContext())
        {
            firstCampaignId = (await SeedDueCampaignAsync(setupDb, firstOccurrenceUtc)).Id;
            secondCampaignId = (await SeedDueCampaignAsync(setupDb, secondOccurrenceUtc)).Id;
        }

        var beforeCommitFailure = new AtomicDispatchTransientFailureInterceptor(
            throwAfterCommit: false);
        await using (var schedulerDb = CreateDbContext(beforeCommitFailure))
        {
            var service = CreateDispatchService(schedulerDb);
            var result = await service.RunSchedulerTickAsync(CancellationToken.None);

            result.CampaignsEvaluated.Should().Be(2);
            result.Dispatched.Should().Be(1);
            result.Errors.Should().Be(1,
                "a direct transient provider exception before commit has no durable tuple to reconcile");
            result.ClaimLost.Should().Be(0);
            schedulerDb.ChangeTracker.Entries().Should().NotContain(entry =>
                entry.State == EntityState.Added
                    || entry.State == EntityState.Modified
                    || entry.State == EntityState.Deleted,
                "the failed direct-provider batch must be detached before the next campaign saves");
        }

        await using (var preCommitVerifyDb = CreateDbContext())
        {
            (await preCommitVerifyDb.SecurityScanJobs.CountAsync(
                    job => job.CampaignId == firstCampaignId))
                .Should().Be(0);
            (await preCommitVerifyDb.CampaignExecutionAuditLogs.CountAsync(
                    audit => audit.CampaignId == firstCampaignId))
                .Should().Be(0);
            (await preCommitVerifyDb.SecurityScanJobs.CountAsync(
                    job => job.CampaignId == secondCampaignId))
                .Should().Be(1,
                    "the next campaign must save without replaying the failed first batch");
        }

        var afterCommitFailure = new AtomicDispatchTransientFailureInterceptor(
            throwAfterCommit: true);
        await using (var schedulerDb = CreateDbContext(afterCommitFailure))
        {
            var service = CreateDispatchService(schedulerDb);
            var result = await service.RunSchedulerTickAsync(CancellationToken.None);

            result.CampaignsEvaluated.Should().Be(1);
            result.Dispatched.Should().Be(0);
            result.ClaimLost.Should().Be(1,
                "a direct transient exception after commit must reconcile the complete durable tuple");
            result.Errors.Should().Be(0);
            schedulerDb.ChangeTracker.Entries().Should().NotContain(entry =>
                entry.State == EntityState.Added
                    || entry.State == EntityState.Modified
                    || entry.State == EntityState.Deleted);
        }

        await using var postCommitVerifyDb = CreateDbContext();
        (await postCommitVerifyDb.SecurityScanJobs.CountAsync(
                job => job.CampaignId == firstCampaignId))
            .Should().Be(1,
                "acknowledgement loss must never create a second occurrence job");
        var firstCampaignAudits = await postCommitVerifyDb.CampaignExecutionAuditLogs
            .Where(audit => audit.CampaignId == firstCampaignId)
            .ToListAsync();
        firstCampaignAudits.Count(audit => audit.Decision == SchedulerDecision.Dispatched)
            .Should().Be(1);
        firstCampaignAudits.Count(audit => audit.Decision == SchedulerDecision.SkippedClaimLost)
            .Should().Be(1);
    }

    private sealed class AtomicDispatchTransientFailureInterceptor(bool throwAfterCommit)
        : SaveChangesInterceptor
    {
        private int _armed;
        private int _hasThrown;

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (IsAtomicDispatch(eventData.Context))
            {
                if (throwAfterCommit)
                {
                    Volatile.Write(ref _armed, 1);
                }
                else
                {
                    ThrowTransientFailureOnce("before commit");
                }
            }

            return ValueTask.FromResult(result);
        }

        public override ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (throwAfterCommit && Volatile.Read(ref _armed) == 1)
            {
                ThrowTransientFailureOnce("after commit acknowledgement was lost");
            }

            return ValueTask.FromResult(result);
        }

        private void ThrowTransientFailureOnce(string stage)
        {
            if (Interlocked.CompareExchange(ref _hasThrown, 1, 0) == 0)
            {
                throw new NpgsqlException(
                    $"Simulated transient provider failure {stage}.",
                    new System.IO.IOException("Simulated connection loss."));
            }
        }

        private static bool IsAtomicDispatch(DbContext? dbContext)
        {
            if (dbContext == null)
            {
                return false;
            }

            return dbContext.ChangeTracker.Entries<ScanCampaign>()
                    .Any(entry => entry.State == EntityState.Modified)
                && dbContext.ChangeTracker.Entries<SecurityScanJob>()
                    .Any(entry => entry.State == EntityState.Added
                        && entry.Entity.CampaignOccurrenceKey != null)
                && dbContext.ChangeTracker.Entries<CampaignExecutionAuditLog>()
                    .Any(entry => entry.State == EntityState.Added
                        && entry.Entity.Decision is SchedulerDecision.Dispatched
                            or SchedulerDecision.QueuedNext);
        }
    }

    [Fact]
    public async Task UnrelatedDatabaseFailure_DoesNotReplayFailedDispatchIntoNextCampaign()
    {
        var firstOccurrenceUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var secondOccurrenceUtc = firstOccurrenceUtc.AddMinutes(1);
        Guid failedCampaignId;
        Guid successfulCampaignId;

        await using (var setupDb = CreateDbContext())
        {
            failedCampaignId = (await SeedDueCampaignAsync(
                setupDb,
                firstOccurrenceUtc,
                SecurityScanProfileType.Deep)).Id;
            successfulCampaignId = (await SeedDueCampaignAsync(
                setupDb,
                secondOccurrenceUtc,
                SecurityScanProfileType.Standard)).Id;

            await setupDb.Database.ExecuteSqlRawAsync(
                """
                ALTER TABLE "security_scan_jobs"
                ADD CONSTRAINT "CK_test_reject_deep_scan_profile"
                CHECK ("ScanProfile" <> 'FullAssessment');
                """);
        }

        CampaignSchedulerTickResult result;
        await using var schedulerDb = CreateDbContext();
        try
        {
            var service = CreateDispatchService(schedulerDb);
            result = await service.RunSchedulerTickAsync(CancellationToken.None);
        }
        finally
        {
            await using var cleanupDb = CreateDbContext();
            await cleanupDb.Database.ExecuteSqlRawAsync(
                """
                ALTER TABLE "security_scan_jobs"
                DROP CONSTRAINT IF EXISTS "CK_test_reject_deep_scan_profile";
                """);
        }

        result.CampaignsEvaluated.Should().Be(2);
        result.Dispatched.Should().Be(1);
        result.Errors.Should().Be(1,
            "the unrelated CHECK violation must propagate to the scheduler tick error boundary");
        result.ClaimLost.Should().Be(0,
            "an unrelated constraint failure must never be reclassified as a lost claim");
        schedulerDb.ChangeTracker.Entries()
            .Should().NotContain(entry => entry.State == EntityState.Added
                || entry.State == EntityState.Modified
                || entry.State == EntityState.Deleted,
                "failed dispatch entries must be detached before the next campaign is saved");

        await using var verifyDb = CreateDbContext();
        var failedCampaign = await verifyDb.ScanCampaigns
            .AsNoTracking()
            .SingleAsync(campaign => campaign.Id == failedCampaignId);
        failedCampaign.ScheduleVersion.Should().Be(1);
        failedCampaign.NextRunUtc.Should().Be(firstOccurrenceUtc);
        failedCampaign.LastRunUtc.Should().BeNull();
        failedCampaign.LastScanJobId.Should().BeNull();
        failedCampaign.LastCampaignOccurrenceKey.Should().BeNull();
        failedCampaign.TotalRunsCount.Should().Be(0);

        (await verifyDb.SecurityScanJobs.CountAsync(job => job.CampaignId == failedCampaignId))
            .Should().Be(0);
        (await verifyDb.CampaignExecutionAuditLogs.CountAsync(
                audit => audit.CampaignId == failedCampaignId))
            .Should().Be(0);

        var successfulJobs = await verifyDb.SecurityScanJobs
            .Where(job => job.CampaignId == successfulCampaignId)
            .ToListAsync();
        successfulJobs.Should().ContainSingle();
        (await verifyDb.CampaignExecutionAuditLogs.CountAsync(
                audit => audit.CampaignId == successfulCampaignId
                    && audit.Decision == SchedulerDecision.Dispatched))
            .Should().Be(1);

        var successfulCampaign = await verifyDb.ScanCampaigns
            .AsNoTracking()
            .SingleAsync(campaign => campaign.Id == successfulCampaignId);
        successfulCampaign.ScheduleVersion.Should().Be(2);
        successfulCampaign.LastScanJobId.Should().Be(successfulJobs[0].Id);
        successfulCampaign.LastCampaignOccurrenceKey.Should().Be(
            successfulJobs[0].CampaignOccurrenceKey);
    }

    private sealed class AtomicDispatchSaveInterceptor(AtomicDispatchSaveGate gate)
        : SaveChangesInterceptor
    {
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (eventData.Context != null)
            {
                await gate.WaitForBothSchedulersAsync(eventData.Context, cancellationToken);
            }

            return result;
        }
    }

    private sealed class AtomicDispatchSaveGate
    {
        private readonly object _sync = new();
        private readonly List<long> _originalScheduleVersions = [];
        private readonly List<DateTime?> _originalScheduledOccurrences = [];
        private readonly TaskCompletionSource<bool> _bothSchedulersArrived =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrivalCount;

        public int ArrivalCount => Volatile.Read(ref _arrivalCount);

        public IReadOnlyList<long> OriginalScheduleVersions
        {
            get
            {
                lock (_sync)
                {
                    return [.. _originalScheduleVersions];
                }
            }
        }

        public IReadOnlyList<DateTime?> OriginalScheduledOccurrences
        {
            get
            {
                lock (_sync)
                {
                    return [.. _originalScheduledOccurrences];
                }
            }
        }

        public async Task WaitForBothSchedulersAsync(DbContext dbContext, CancellationToken cancellationToken)
        {
            var campaignEntry = dbContext.ChangeTracker.Entries<ScanCampaign>()
                .SingleOrDefault(entry => entry.State == EntityState.Modified);
            var hasAddedJob = dbContext.ChangeTracker.Entries<SecurityScanJob>()
                .Any(entry => entry.State == EntityState.Added
                    && entry.Entity.CampaignOccurrenceKey != null);
            var hasAddedDispatchAudit = dbContext.ChangeTracker.Entries<CampaignExecutionAuditLog>()
                .Any(entry => entry.State == EntityState.Added
                    && entry.Entity.Decision is SchedulerDecision.Dispatched or SchedulerDecision.QueuedNext);

            if (campaignEntry == null || !hasAddedJob || !hasAddedDispatchAudit)
            {
                return;
            }

            var originalVersion = campaignEntry.OriginalValues
                .GetValue<long>(nameof(ScanCampaign.ScheduleVersion));
            var originalOccurrence = campaignEntry.OriginalValues
                .GetValue<DateTime?>(nameof(ScanCampaign.NextRunUtc));

            lock (_sync)
            {
                _originalScheduleVersions.Add(originalVersion);
                _originalScheduledOccurrences.Add(originalOccurrence);
            }

            var arrivals = Interlocked.Increment(ref _arrivalCount);
            if (arrivals > 2)
            {
                throw new InvalidOperationException("Atomic dispatch save gate received more than two participants.");
            }

            if (arrivals == 2)
            {
                _bothSchedulersArrived.TrySetResult(true);
            }

            await _bothSchedulersArrived.Task.WaitAsync(
                TimeSpan.FromSeconds(15),
                cancellationToken);
        }
    }
}
