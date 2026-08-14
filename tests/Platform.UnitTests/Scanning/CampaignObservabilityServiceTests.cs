using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

/// <summary>
/// Unit tests for CampaignObservabilityService.
/// Verifies health evaluation precedence, history correlation, diagnostics,
/// and tenant isolation on the read model.
/// </summary>
public sealed class CampaignObservabilityServiceTests : IDisposable
{
    private readonly PlatformDbContext _db;
    private readonly CampaignSchedulerOptions _options;
    private readonly CampaignObservabilityService _service;

    private readonly Guid _tenantA = Guid.NewGuid();
    private readonly Guid _tenantB = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public CampaignObservabilityServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("CampaignObservability_" + Guid.NewGuid())
            .Options;

        _db = new PlatformDbContext(dbOptions);
        _options = new CampaignSchedulerOptions
        {
            GlobalEnabled = true,
            TickIntervalSeconds = 30,
            MaxCampaignsPerTick = 50,
            StuckJobThresholdMinutes = 60,
            RecoveryIntervalSeconds = 300,
            HeartbeatIntervalSeconds = 120
        };

        _service = new CampaignObservabilityService(
            _db,
            Options.Create(_options),
            NullLogger<CampaignObservabilityService>.Instance);

        // Seed base repository and target
        _db.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "PaymentCore",
            FullName = "enterprise/PaymentCore",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/PaymentCore",
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Payment Gateway",
            BaseUrl = "https://gateway.payment.internal",
            TargetType = "WebEndpoint",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    // =========================================================================
    // 1. HEALTH STATUS EVALUATION & PRECEDENCE
    // Precedence: FailClosed > Unavailable > Degraded > NotConfigured > Healthy
    // =========================================================================

    [Fact]
    public async Task GetTenantHealth_NoCampaigns_ReturnsNotConfigured()
    {
        var health = await _service.GetTenantHealthAsync(_tenantA, CancellationToken.None);

        health.Status.Should().Be(CampaignOperationalHealthStatus.NotConfigured);
        health.TotalCampaigns.Should().Be(0);
        health.ActiveCampaigns.Should().Be(0);
    }

    [Fact]
    public async Task GetTenantHealth_ActiveCampaign_HealthyWorker_ReturnsHealthy()
    {
        // Active campaign
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Healthy Campaign",
            Status = CampaignStatus.Active,
            ScanProfile = SecurityScanProfileType.Standard,
            ScheduleType = ScheduleType.Interval,
            IntervalDuration = TimeSpan.FromHours(24),
            TimeZoneId = "UTC",
            NextRunUtc = DateTime.UtcNow.AddHours(2), // Future run
            CreatedAtUtc = DateTime.UtcNow
        });

        // Fresh audit log (worker alive)
        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = Guid.NewGuid(),
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddSeconds(-10), // 10s ago
            Reason = "Scheduled tick"
        });
        await _db.SaveChangesAsync();

        var health = await _service.GetTenantHealthAsync(_tenantA, CancellationToken.None);

        health.Status.Should().Be(CampaignOperationalHealthStatus.Healthy);
        health.SchedulerWorkerAlive.Should().BeTrue();
        health.ActiveCampaigns.Should().Be(1);
        health.OverdueCampaignsCount.Should().Be(0);
    }

    [Fact]
    public async Task GetTenantHealth_ActiveCampaign_StaleWorkerHeartbeat_ReturnsUnavailable()
    {
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Stale Worker Campaign",
            Status = CampaignStatus.Active,
            NextRunUtc = DateTime.UtcNow.AddHours(1),
            CreatedAtUtc = DateTime.UtcNow
        });

        // Audit timestamp is 10 minutes old (threshold is 90s)
        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = Guid.NewGuid(),
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            Reason = "Stale tick"
        });
        await _db.SaveChangesAsync();

        var health = await _service.GetTenantHealthAsync(_tenantA, CancellationToken.None);

        health.Status.Should().Be(CampaignOperationalHealthStatus.Unavailable);
        health.SchedulerWorkerAlive.Should().BeFalse();
        health.StatusReason.Should().Contain("Scheduler worker heartbeat is stale");
    }

    [Fact]
    public async Task GetTenantHealth_AutoPausedCampaign_ReturnsDegraded()
    {
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "AutoPaused Campaign",
            Status = CampaignStatus.AutoPaused,
            ConsecutiveFailuresCount = 5,
            MaxConsecutiveFailures = 5,
            CreatedAtUtc = DateTime.UtcNow
        });

        // Worker is alive
        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = Guid.NewGuid(),
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddSeconds(-15),
            Reason = "Fresh tick"
        });
        await _db.SaveChangesAsync();

        var health = await _service.GetTenantHealthAsync(_tenantA, CancellationToken.None);

        health.Status.Should().Be(CampaignOperationalHealthStatus.Degraded);
        health.AutoPausedCampaigns.Should().Be(1);
        health.StatusReason.Should().Contain("AutoPaused");
    }

    [Fact]
    public async Task GetTenantHealth_OverdueCampaign_ReturnsDegraded()
    {
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Overdue Campaign",
            Status = CampaignStatus.Active,
            NextRunUtc = DateTime.UtcNow.AddMinutes(-15), // Due 15 mins ago (overdue threshold is 5 mins)
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = Guid.NewGuid(),
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddSeconds(-15),
            Reason = "Fresh tick"
        });
        await _db.SaveChangesAsync();

        var health = await _service.GetTenantHealthAsync(_tenantA, CancellationToken.None);

        health.Status.Should().Be(CampaignOperationalHealthStatus.Degraded);
        health.OverdueCampaignsCount.Should().Be(1);
        health.StatusReason.Should().Contain("overdue for scheduled scan execution");
    }

    // =========================================================================
    // 2. CORRELATED EXECUTION HISTORY
    // =========================================================================

    [Fact]
    public async Task GetCampaignExecutionHistory_JoinsAuditLogWithScanJobDetails()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Audited Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });

        var scanJobId = Guid.NewGuid();
        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = scanJobId,
            CampaignId = campaignId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://gateway.payment.internal",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            TotalFindingsCount = 4,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc = DateTime.UtcNow.AddMinutes(-3), // Duration = 120s
            CampaignOccurrenceKey = "abc123canonicalkey",
            JobVersion = 1,
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5)
        });

        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaignId,
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            DispatchedScanJobId = scanJobId,
            Reason = "Scheduled occurrence dispatched"
        });
        await _db.SaveChangesAsync();

        var history = await _service.GetCampaignExecutionHistoryAsync(
            _tenantA, campaignId, page: 1, pageSize: 10, ct: CancellationToken.None);

        history.Should().HaveCount(1);
        var entry = history[0];
        entry.CampaignId.Should().Be(campaignId);
        entry.Decision.Should().Be(SchedulerDecision.Dispatched);
        entry.ScanJobId.Should().Be(scanJobId);
        entry.ScanJobStatus.Should().Be(SecurityScanJobStatus.Completed);
        entry.TotalFindingsCount.Should().Be(4);
        entry.ScanDurationSeconds.Should().BeApproximately(120, 1.0);
        entry.OccurrenceKey.Should().Be("abc123canonicalkey");
    }

    [Fact]
    public async Task GetCampaignExecutionHistory_CrossTenant_ReturnsEmpty()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA, // Belongs to Tenant A
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Tenant A Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaignId,
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow,
            Reason = "Dispatched"
        });
        await _db.SaveChangesAsync();

        // Tenant B requests Tenant A's history
        var history = await _service.GetCampaignExecutionHistoryAsync(
            _tenantB, campaignId, page: 1, pageSize: 10, ct: CancellationToken.None);

        history.Should().BeEmpty("cross-tenant history access must return empty / unauthorized");
    }

    // =========================================================================
    // 3. CAMPAIGN DIAGNOSTICS & RECOVERY SOURCING
    // =========================================================================

    [Fact]
    public async Task GetCampaignDiagnostics_ReturnsOverdueAndAuditSourcedRecoveries()
    {
        var campaignId = Guid.NewGuid();
        var nextRun = DateTime.UtcNow.AddMinutes(-30);
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Diagnostic Campaign",
            Status = CampaignStatus.AutoPaused,
            ConsecutiveFailuresCount = 3,
            MaxConsecutiveFailures = 3,
            AutoPauseOnConsecutiveFailures = true,
            NextRunUtc = nextRun,
            UpdatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1)
        });

        // Add recovery audit records (proves recoveries are sourced from immutable audit log)
        var recoveryJobId = Guid.NewGuid();
        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaignId,
            TenantId = _tenantA,
            Decision = SchedulerDecision.RecoveredStuck,
            TriggerSource = "RecoveryWorker",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            DispatchedScanJobId = recoveryJobId,
            Reason = "Stuck heartbeat threshold exceeded. Transitioned to TimedOut.",
            MetadataJson = "{\"workerId\":\"worker-alpha\",\"threshold\":60}"
        });
        await _db.SaveChangesAsync();

        var diag = await _service.GetCampaignDiagnosticsAsync(_tenantA, campaignId, CancellationToken.None);

        diag.Should().NotBeNull();
        diag!.CampaignName.Should().Be("Diagnostic Campaign");
        diag.Status.Should().Be(CampaignStatus.AutoPaused);
        diag.ConsecutiveFailuresCount.Should().Be(3);
        diag.AutoPauseReason.Should().Contain("Exceeded maximum consecutive failure threshold (3/3)");
        diag.RecentRecoveries.Should().HaveCount(1);
        diag.RecentRecoveries[0].TriggerSource.Should().Be("RecoveryWorker");
        diag.RecentRecoveries[0].ScanJobId.Should().Be(recoveryJobId);
    }

    // =========================================================================
    // 4. TENANT WINDOW METRICS
    // =========================================================================

    [Fact]
    public async Task GetTenantWindowMetrics_CalculatesAccurateAggregatePercentages()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Metrics Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });

        var jobSuccess = Guid.NewGuid();
        var jobFail = Guid.NewGuid();

        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = jobSuccess,
            CampaignId = campaignId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://gateway.payment.internal",
            Status = SecurityScanJobStatus.Completed,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-30),
            CompletedAtUtc = DateTime.UtcNow.AddMinutes(-28), // 120s
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-30)
        });

        _db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = jobFail,
            CampaignId = campaignId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://gateway.payment.internal",
            Status = SecurityScanJobStatus.Failed,
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-10)
        });

        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaignId,
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddMinutes(-30),
            DispatchedScanJobId = jobSuccess,
            Reason = "Dispatched"
        });

        _db.CampaignExecutionAuditLogs.Add(new CampaignExecutionAuditLog
        {
            Id = Guid.NewGuid(),
            CampaignId = campaignId,
            TenantId = _tenantA,
            Decision = SchedulerDecision.Dispatched,
            TriggerSource = "CampaignScheduler",
            ScheduleVersion = 1,
            EvaluatedAtUtc = DateTime.UtcNow.AddMinutes(-10),
            DispatchedScanJobId = jobFail,
            Reason = "Dispatched"
        });
        await _db.SaveChangesAsync();

        var metrics = await _service.GetTenantWindowMetricsAsync(
            _tenantA, TimeSpan.FromHours(24), CancellationToken.None);

        metrics.TotalEvaluations.Should().Be(2);
        metrics.DispatchedCount.Should().Be(2);
        metrics.CompletedScansCount.Should().Be(1);
        metrics.FailedScansCount.Should().Be(1);
        metrics.SuccessRatePercentage.Should().Be(50.0);
        metrics.AverageScanDurationSeconds.Should().BeApproximately(120.0, 1.0);
    }
}
