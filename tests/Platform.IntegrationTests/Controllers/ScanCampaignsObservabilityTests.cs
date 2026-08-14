using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Configuration;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class ScanCampaignsObservabilityTests : IDisposable
{
    private readonly PlatformDbContext _db;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly ScanCampaignService _campaignService;
    private readonly CampaignObservabilityService _observabilityService;
    private readonly ScanCampaignsController _controller;

    private readonly Guid _tenantA = Guid.NewGuid();
    private readonly Guid _tenantB = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanCampaignsObservabilityTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanCampaignsObservabilityDb_" + Guid.NewGuid())
            .Options;
        _db = new PlatformDbContext(dbOptions);

        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.UserId).Returns(_tenantA);
        _mockUser.Setup(u => u.IsAuthenticated).Returns(true);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        var calculator = new CampaignScheduleCalculator(NullLogger<CampaignScheduleCalculator>.Instance);
        _campaignService = new ScanCampaignService(_db, calculator, NullLogger<ScanCampaignService>.Instance);

        var options = Options.Create(new CampaignSchedulerOptions
        {
            GlobalEnabled = true,
            TickIntervalSeconds = 30
        });
        _observabilityService = new CampaignObservabilityService(_db, options, NullLogger<CampaignObservabilityService>.Instance);

        _controller = new ScanCampaignsController(_campaignService, _observabilityService, _mockUser.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        // Seed base repository and target
        _db.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "ObsRepo",
            FullName = "enterprise/ObsRepo",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/ObsRepo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "ObsTarget",
            BaseUrl = "https://target.internal",
            TargetType = "WebEndpoint",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task GetHealth_Returns200WithTenantHealthStatus()
    {
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Tenant A Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        var result = await _controller.GetHealth(CancellationToken.None);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var health = okResult.Value.Should().BeOfType<CampaignOperationalHealthDto>().Subject;

        health.TenantId.Should().Be(_tenantA);
        health.TotalCampaigns.Should().Be(1);
        health.ActiveCampaigns.Should().Be(1);
    }

    [Fact]
    public async Task GetMetrics_Returns200WithWindowMetrics()
    {
        var result = await _controller.GetMetrics("24h", CancellationToken.None);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var metrics = okResult.Value.Should().BeOfType<CampaignWindowMetricsDto>().Subject;

        metrics.Window.Should().Be(TimeSpan.FromHours(24));
    }

    [Fact]
    public async Task GetExecutionHistory_Returns200AndCorrelatedHistory()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "History Campaign",
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
            TargetUrl = "https://target.internal",
            Status = SecurityScanJobStatus.Completed,
            TotalFindingsCount = 2,
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
            DispatchedScanJobId = scanJobId,
            Reason = "Dispatched"
        });
        await _db.SaveChangesAsync();

        var result = await _controller.GetExecutionHistory(campaignId, 1, 10, null, null, CancellationToken.None);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var history = okResult.Value.Should().BeAssignableTo<IReadOnlyList<CampaignExecutionHistoryEntryDto>>().Subject;

        history.Should().HaveCount(1);
        history[0].ScanJobId.Should().Be(scanJobId);
        history[0].TotalFindingsCount.Should().Be(2);
    }

    [Fact]
    public async Task GetDiagnostics_Returns200ForOwnedCampaign()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantA,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Diagnostics Campaign",
            Status = CampaignStatus.AutoPaused,
            ConsecutiveFailuresCount = 5,
            MaxConsecutiveFailures = 5,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        var result = await _controller.GetDiagnostics(campaignId, CancellationToken.None);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var diag = okResult.Value.Should().BeOfType<CampaignDiagnosticsDto>().Subject;

        diag.CampaignId.Should().Be(campaignId);
        diag.Status.Should().Be(CampaignStatus.AutoPaused);
    }

    [Fact]
    public async Task GetDiagnostics_CrossTenant_Returns404()
    {
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantB, // Tenant B's campaign
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Tenant B Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        // Tenant A calls diagnostics for Tenant B's campaign
        var result = await _controller.GetDiagnostics(campaignId, CancellationToken.None);
        result.Result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task NonAdmin_CannotSpoofTenantHeader()
    {
        // Add campaign owned by Tenant B
        var campaignId = Guid.NewGuid();
        _db.ScanCampaigns.Add(new ScanCampaign
        {
            Id = campaignId,
            TenantId = _tenantB,
            RepositoryId = _repoId,
            SecurityTargetId = _targetId,
            Name = "Tenant B Campaign",
            Status = CampaignStatus.Active,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();

        // Non-admin Tenant A supplies X-Tenant-ID header pretending to be Tenant B
        _controller.HttpContext.Request.Headers["X-Tenant-ID"] = _tenantB.ToString();

        var result = await _controller.GetDiagnostics(campaignId, CancellationToken.None);
        result.Result.Should().BeOfType<NotFoundObjectResult>(
            "non-admin user must not be able to override tenant identity via X-Tenant-ID header");
    }
}
