using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanCampaignServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly CampaignScheduleCalculator _calculator;
    private readonly ScanCampaignService _service;

    private readonly Guid _tenantId = Guid.NewGuid();
    private readonly Guid _userId = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanCampaignServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanCampaignServiceTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _calculator = new CampaignScheduleCalculator(NullLogger<CampaignScheduleCalculator>.Instance);
        _service = new ScanCampaignService(_dbContext, _calculator, NullLogger<ScanCampaignService>.Instance);

        // Seed Repository
        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "PaymentService",
            FullName = "enterprise/PaymentService",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/PaymentService",
            CreatedAtUtc = DateTime.UtcNow
        });

        // Seed SecurityTarget
        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Payment API Gateway",
            TargetType = "WebEndpoint",
            BaseUrl = "https://api.payments.enterprise.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    // =========================================================================
    // 1. CREATION & TENANT OWNERSHIP CHAIN VALIDATION
    // =========================================================================

    [Fact]
    public async Task CreateCampaign_ValidOwnershipChain_CreatesActiveCampaignWithInitialCursor()
    {
        var request = new CreateCampaignRequest(
            Name: "Daily Payment Security Audit",
            Description: "Continuous daily assessment of payment API",
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScanProfile: SecurityScanProfileType.Standard,
            ScheduleType: ScheduleType.Interval,
            CronExpression: null,
            IntervalMinutes: 1440, // 24 hours
            TimeZoneId: "UTC",
            ConcurrencyPolicy: CampaignConcurrencyPolicy.SkipIfRunning
        );

        var result = await _service.CreateCampaignAsync(_tenantId, _userId, request, CancellationToken.None);

        result.Should().NotBeNull();
        result.Name.Should().Be("Daily Payment Security Audit");
        result.TenantId.Should().Be(_tenantId);
        result.RepositoryId.Should().Be(_repoId);
        result.SecurityTargetId.Should().Be(_targetId);
        result.Status.Should().Be(CampaignStatus.Active);
        result.ScheduleVersion.Should().Be(1);
        result.NextRunUtc.Should().NotBeNull();
        result.NextRunUtc.Should().BeAfter(DateTime.UtcNow.AddHours(23));

        var dbCampaign = await _dbContext.ScanCampaigns.FirstOrDefaultAsync(c => c.Id == result.Id);
        dbCampaign.Should().NotBeNull();
        dbCampaign!.Status.Should().Be(CampaignStatus.Active);
    }

    [Fact]
    public async Task CreateCampaign_NonExistentRepository_ThrowsKeyNotFoundException()
    {
        var request = new CreateCampaignRequest(
            Name: "Orphan Campaign",
            Description: null,
            RepositoryId: Guid.NewGuid(), // Invalid repo
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 60
        );

        var act = () => _service.CreateCampaignAsync(_tenantId, _userId, request, CancellationToken.None);
        await act.Should().ThrowAsync<KeyNotFoundException>().WithMessage("*Repository*not found*");
    }

    [Fact]
    public async Task CreateCampaign_DisabledTarget_ThrowsInvalidOperationException()
    {
        var disabledTargetId = Guid.NewGuid();
        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = disabledTargetId,
            Name = "Disabled Target",
            BaseUrl = "https://disabled.com",
            Enabled = false
        });
        await _dbContext.SaveChangesAsync();

        var request = new CreateCampaignRequest(
            Name: "Campaign on Disabled Target",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: disabledTargetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 60
        );

        var act = () => _service.CreateCampaignAsync(_tenantId, _userId, request, CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*disabled SecurityTarget*");
    }

    // =========================================================================
    // 2. PAUSE, RESUME & OPTIMISTIC CONCURRENCY VERSIONING
    // =========================================================================

    [Fact]
    public async Task PauseAndResume_UpdatesStatus_ClearsAndRecalculatesNextRun_AndIncrementsVersion()
    {
        var createRequest = new CreateCampaignRequest(
            Name: "Audited Campaign",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 120
        );

        var campaign = await _service.CreateCampaignAsync(_tenantId, _userId, createRequest, CancellationToken.None);
        campaign.ScheduleVersion.Should().Be(1);

        // Pause
        var paused = await _service.PauseCampaignAsync(_tenantId, campaign.Id, "Maintenance window", CancellationToken.None);
        paused.Status.Should().Be(CampaignStatus.Paused);
        paused.NextRunUtc.Should().BeNull();
        paused.ScheduleVersion.Should().Be(2);

        // Resume
        var resumed = await _service.ResumeCampaignAsync(_tenantId, campaign.Id, CancellationToken.None);
        resumed.Status.Should().Be(CampaignStatus.Active);
        resumed.NextRunUtc.Should().NotBeNull();
        resumed.ScheduleVersion.Should().Be(3);
    }

    // =========================================================================
    // 3. CONCURRENCY POLICIES & TRIGGER RUN NOW EVALUATION
    // =========================================================================

    [Fact]
    public async Task TriggerRunNow_NoActiveJobs_DispatchesJob_AndRecordsAuditLog()
    {
        var campaign = await _service.CreateCampaignAsync(_tenantId, _userId, new CreateCampaignRequest(
            Name: "On Demand Test",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 120,
            ConcurrencyPolicy: CampaignConcurrencyPolicy.SkipIfRunning
        ), CancellationToken.None);

        var result = await _service.TriggerRunNowAsync(_tenantId, _userId, campaign.Id, CancellationToken.None);

        result.Decision.Should().Be(SchedulerDecision.Dispatched);
        result.DispatchedScanJobId.Should().NotBeNull();

        var job = await _dbContext.SecurityScanJobs.FindAsync(result.DispatchedScanJobId!.Value);
        job.Should().NotBeNull();
        job!.CampaignId.Should().Be(campaign.Id);
        job.TriggeredBy.Should().Be("CampaignRunNow");
        job.Status.Should().Be(SecurityScanJobStatus.Queued);

        // Verify audit log
        var logs = await _service.GetAuditLogsAsync(_tenantId, campaign.Id, 1, 10, CancellationToken.None);
        logs.Should().ContainSingle(l => l.Decision == SchedulerDecision.Dispatched);
    }

    [Fact]
    public async Task TriggerRunNow_SkipIfRunning_WhenJobIsRunning_SkipsTrigger()
    {
        var campaign = await _service.CreateCampaignAsync(_tenantId, _userId, new CreateCampaignRequest(
            Name: "SkipIfRunning Campaign",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 120,
            ConcurrencyPolicy: CampaignConcurrencyPolicy.SkipIfRunning
        ), CancellationToken.None);

        // Simulate an already running job
        _dbContext.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            Status = SecurityScanJobStatus.Running,
            TargetUrl = "https://api.payments.enterprise.com",
            CreatedAtUtc = DateTime.UtcNow
        });
        await _dbContext.SaveChangesAsync();

        var result = await _service.TriggerRunNowAsync(_tenantId, _userId, campaign.Id, CancellationToken.None);

        result.Decision.Should().Be(SchedulerDecision.SkippedAlreadyRunning);
        result.DispatchedScanJobId.Should().BeNull();

        var logs = await _service.GetAuditLogsAsync(_tenantId, campaign.Id, 1, 10, CancellationToken.None);
        logs.Should().ContainSingle(l => l.Decision == SchedulerDecision.SkippedAlreadyRunning);
    }

    [Fact]
    public async Task TriggerRunNow_QueueNext_WhenRunning_EnqueuesOneJob_AndRejectsSecondWhenFull()
    {
        var campaign = await _service.CreateCampaignAsync(_tenantId, _userId, new CreateCampaignRequest(
            Name: "QueueNext Campaign",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 120,
            ConcurrencyPolicy: CampaignConcurrencyPolicy.QueueNext
        ), CancellationToken.None);

        // Active running job
        _dbContext.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            CampaignId = campaign.Id,
            Status = SecurityScanJobStatus.Running,
            TargetUrl = "https://api.payments.enterprise.com",
            CreatedAtUtc = DateTime.UtcNow
        });
        await _dbContext.SaveChangesAsync();

        // 1st Trigger: Should enqueue job #1
        var trigger1 = await _service.TriggerRunNowAsync(_tenantId, _userId, campaign.Id, CancellationToken.None);
        trigger1.Decision.Should().Be(SchedulerDecision.QueuedNext);
        trigger1.DispatchedScanJobId.Should().NotBeNull();

        // 2nd Trigger: Pending job already queued -> Queue depth 1 ceiling reached -> SkippedQueueFull
        var trigger2 = await _service.TriggerRunNowAsync(_tenantId, _userId, campaign.Id, CancellationToken.None);
        trigger2.Decision.Should().Be(SchedulerDecision.SkippedQueueFull);
        trigger2.DispatchedScanJobId.Should().BeNull();

        // Verify only 1 queued job exists in database
        var queuedCount = await _dbContext.SecurityScanJobs
            .CountAsync(j => j.CampaignId == campaign.Id && j.Status == SecurityScanJobStatus.Queued);
        queuedCount.Should().Be(1);
    }
}
