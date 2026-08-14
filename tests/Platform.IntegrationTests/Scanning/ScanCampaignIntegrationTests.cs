using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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

namespace Platform.IntegrationTests.Scanning;

public class ScanCampaignIntegrationTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly CampaignScheduleCalculator _calculator;
    private readonly ScanCampaignService _service;

    private readonly Guid _tenantA = Guid.NewGuid();
    private readonly Guid _tenantB = Guid.NewGuid();
    private readonly Guid _userA = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanCampaignIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanCampaignIntegrationTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _calculator = new CampaignScheduleCalculator(NullLogger<CampaignScheduleCalculator>.Instance);
        _service = new ScanCampaignService(_dbContext, _calculator, NullLogger<ScanCampaignService>.Instance);

        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "CoreBankingApi",
            FullName = "enterprise/CoreBankingApi",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/CoreBankingApi",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Banking Gateway Endpoint",
            TargetType = "WebEndpoint",
            BaseUrl = "https://api.banking.enterprise.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private ScanCampaignsController CreateController(Guid tenantId, Guid userId)
    {
        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns(userId);
        mockUser.Setup(u => u.IsAuthenticated).Returns(true);
        mockUser.Setup(u => u.IsPlatformAdmin).Returns(true);

        var options = Options.Create(new CampaignSchedulerOptions());
        var obsService = new CampaignObservabilityService(_dbContext, options, NullLogger<CampaignObservabilityService>.Instance);

        var controller = new ScanCampaignsController(_service, obsService, mockUser.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        controller.Request.Headers["X-Tenant-ID"] = tenantId.ToString();
        return controller;
    }

    [Fact]
    public async Task ScanCampaignController_CompleteCrudAndRunNowLifecycle()
    {
        var controller = CreateController(_tenantA, _userA);

        // 1. Create Campaign
        var createRequest = new CreateCampaignRequest(
            Name: "Weekly Deep Banking Scan",
            Description: "Continuous deep security evaluation",
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScanProfile: SecurityScanProfileType.Deep,
            ScheduleType: ScheduleType.Cron,
            CronExpression: "0 3 * * 0", // Every Sunday at 3 AM
            TimeZoneId: "UTC",
            ConcurrencyPolicy: CampaignConcurrencyPolicy.QueueNext
        );

        var createResult = await controller.CreateCampaign(createRequest, CancellationToken.None);
        var createdAction = createResult.Result as CreatedAtActionResult;
        createdAction.Should().NotBeNull();
        var campaignDto = createdAction!.Value as ScanCampaignDto;
        campaignDto.Should().NotBeNull();
        campaignDto!.Name.Should().Be("Weekly Deep Banking Scan");
        campaignDto.Status.Should().Be(CampaignStatus.Active);
        campaignDto.NextRunUtc.Should().NotBeNull();

        // 2. Query Single Campaign
        var getResult = await controller.GetCampaign(campaignDto.Id, CancellationToken.None);
        var okGet = getResult.Result as OkObjectResult;
        okGet.Should().NotBeNull();
        var fetchedDto = okGet!.Value as ScanCampaignDto;
        fetchedDto!.Id.Should().Be(campaignDto.Id);

        // 3. Trigger Run Now
        var runNowResult = await controller.TriggerRunNow(campaignDto.Id, CancellationToken.None);
        var okRun = runNowResult.Result as OkObjectResult;
        okRun.Should().NotBeNull();
        var runResultDto = okRun!.Value as CampaignRunNowResult;
        runResultDto!.Decision.Should().Be(SchedulerDecision.Dispatched);
        runResultDto.DispatchedScanJobId.Should().NotBeNull();

        // 4. Query Audit Logs
        var auditResult = await controller.GetAuditLogs(campaignDto.Id, 1, 10, CancellationToken.None);
        var okAudit = auditResult.Result as OkObjectResult;
        okAudit.Should().NotBeNull();
        var logs = okAudit!.Value as IReadOnlyList<CampaignExecutionAuditLogDto>;
        logs.Should().NotBeEmpty();
        logs!.First().Decision.Should().Be(SchedulerDecision.Dispatched);

        // 5. Pause Campaign
        var pauseResult = await controller.PauseCampaign(campaignDto.Id, "Maintenance", CancellationToken.None);
        var okPause = pauseResult.Result as OkObjectResult;
        var pausedDto = okPause!.Value as ScanCampaignDto;
        pausedDto!.Status.Should().Be(CampaignStatus.Paused);
        pausedDto.NextRunUtc.Should().BeNull();

        // 6. Resume Campaign
        var resumeResult = await controller.ResumeCampaign(campaignDto.Id, CancellationToken.None);
        var okResume = resumeResult.Result as OkObjectResult;
        var resumedDto = okResume!.Value as ScanCampaignDto;
        resumedDto!.Status.Should().Be(CampaignStatus.Active);
        resumedDto.NextRunUtc.Should().NotBeNull();

        // 7. Archive Campaign
        var archiveResult = await controller.ArchiveCampaign(campaignDto.Id, CancellationToken.None);
        var okArchive = archiveResult.Result as OkObjectResult;
        var archivedDto = okArchive!.Value as ScanCampaignDto;
        archivedDto!.Status.Should().Be(CampaignStatus.Archived);
        archivedDto.NextRunUtc.Should().BeNull();

        // 8. Verify historical SecurityScanJob is preserved
        var dbJob = await _dbContext.SecurityScanJobs.FindAsync(runResultDto.DispatchedScanJobId!.Value);
        dbJob.Should().NotBeNull();
        dbJob!.CampaignId.Should().Be(campaignDto.Id);
    }

    [Fact]
    public async Task ScanCampaignController_TenantIsolation_CrossTenantAccessReturnsNotFound()
    {
        var controllerA = CreateController(_tenantA, _userA);
        var controllerB = CreateController(_tenantB, Guid.NewGuid());

        var createResult = await controllerA.CreateCampaign(new CreateCampaignRequest(
            Name: "Tenant A Private Campaign",
            Description: null,
            RepositoryId: _repoId,
            SecurityTargetId: _targetId,
            ScheduleType: ScheduleType.Interval,
            IntervalMinutes: 60
        ), CancellationToken.None);

        var campaignDto = (createResult.Result as CreatedAtActionResult)!.Value as ScanCampaignDto;

        // Tenant B attempts to read Tenant A's campaign
        var getResult = await controllerB.GetCampaign(campaignDto!.Id, CancellationToken.None);
        getResult.Result.Should().BeOfType<NotFoundObjectResult>();

        // Tenant B attempts to trigger Run Now on Tenant A's campaign
        var runResult = await controllerB.TriggerRunNow(campaignDto.Id, CancellationToken.None);
        runResult.Result.Should().BeOfType<NotFoundObjectResult>();

        // Tenant B attempts to pause Tenant A's campaign
        var pauseResult = await controllerB.PauseCampaign(campaignDto.Id, "Intrusion", CancellationToken.None);
        pauseResult.Result.Should().BeOfType<NotFoundObjectResult>();
    }
}
