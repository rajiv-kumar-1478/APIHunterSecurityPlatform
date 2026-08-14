using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class SecurityScanControllerTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly ScanJobService _scanJobService;
    private readonly ScanToolHealthService _toolHealthService;
    private readonly InMemoryScanProviderSecretStore _secretStore;
    private readonly SecurityScanController _controller;
    private readonly Guid _adminUserId = Guid.NewGuid();

    public SecurityScanControllerTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("SecurityScanControllerDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.UserId).Returns(_adminUserId);
        _mockUser.Setup(u => u.IsAuthenticated).Returns(true);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(true);

        _toolRegistryService = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _scanJobService = new ScanJobService(_dbContext, _mockUser.Object, _toolRegistryService, NullLogger<ScanJobService>.Instance);
        _toolHealthService = new ScanToolHealthService(_toolRegistryService, NullLogger<ScanToolHealthService>.Instance);
        _secretStore = new InMemoryScanProviderSecretStore();
        var postProcessor = new ScanPostExecutionProcessor(_dbContext, _scanJobService, NullLogger<ScanPostExecutionProcessor>.Instance);

        _controller = new SecurityScanController(_scanJobService, _toolRegistryService, _toolHealthService, _secretStore, postProcessor);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    [Fact]
    public async Task Test1_GetCapabilities_Returns200AndManifest()
    {
        var result = await _controller.GetCapabilities(default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var capabilities = okResult.Value.Should().BeAssignableTo<IReadOnlyList<ScanCapabilityDto>>().Subject;

        capabilities.Should().NotBeNull();
        capabilities.Should().Contain(c => c.CapabilityKey == "SubdomainEnumeration");
        capabilities.Should().Contain(c => c.CapabilityKey == "HttpProbing");
    }

    [Fact]
    public async Task Test2_GetProviders_Returns200AndBugHunterProvider()
    {
        var result = await _controller.GetProviders(default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var providers = okResult.Value.Should().BeAssignableTo<IReadOnlyList<ScanProviderDto>>().Subject;

        providers.Should().NotBeNull();
        providers.Should().Contain(p => p.ProviderKey == "bughunter");
    }

    [Fact]
    public async Task Test3_GetTools_Returns200List()
    {
        var result = await _controller.GetTools(default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var tools = okResult.Value.Should().BeAssignableTo<IReadOnlyList<ScanToolDto>>().Subject;

        tools.Should().NotBeNull();
    }

    [Fact]
    public async Task Test4_CreateJob_Succeeds_ForAuthorizedTarget()
    {
        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = Guid.NewGuid(),
            Name = "Authorized Web Target",
            BaseUrl = "https://authorized.example.com",
            Enabled = true
        });
        await _dbContext.SaveChangesAsync();

        var request = new CreateScanJobRequest(
            RepositoryId: null,
            TargetId: null,
            TargetUrl: "https://authorized.example.com",
            ScanProfile: SecurityScanProfileType.Recon,
            ProviderKey: "bughunter"
        );

        var result = await _controller.CreateJob(request, default);
        var createdResult = result.Result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var job = createdResult.Value.Should().BeOfType<SecurityScanJob>().Subject;

        job.Should().NotBeNull();
        job.TargetUrl.Should().Be("https://authorized.example.com");
        job.Status.Should().Be(SecurityScanJobStatus.Queued);
    }

    [Fact]
    public async Task Test5_GetRuntimeHealth_ReturnsStructuredStatus()
    {
        var result = await _controller.GetRuntimeHealth(default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var health = okResult.Value.Should().BeOfType<ScannerRuntimeHealthDto>().Subject;

        health.Should().NotBeNull();
        health.Runtime.Should().NotBeNull();
        health.Provenance.Should().NotBeNull();
        health.Provenance.ImageDigestRequired.Should().BeTrue();
        health.Egress.Should().NotBeNull();
        health.Limits.Should().NotBeNull();
        health.Limits.CpuCores.Should().Be(2.0);
    }

    [Fact]
    public async Task Test6_GetJobReceipt_Returns200WithReceipt()
    {
        var receipt = new ScanExecutionReceipt(
            JobId: Guid.NewGuid(),
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-2),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:abc", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow, 60000, 512, 1, 1, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 1,
            TotalFindingsUpdated: 0,
            Summary: "Scan completed."
        );

        var job = new SecurityScanJob
        {
            Id = receipt.JobId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = System.Text.Json.JsonSerializer.Serialize(receipt),
            RequestedByUserId = _adminUserId
        };

        _dbContext.SecurityScanJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetJobReceipt(job.Id, default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var returnedReceipt = okResult.Value.Should().BeOfType<ScanExecutionReceipt>().Subject;

        returnedReceipt.JobId.Should().Be(job.Id);
        returnedReceipt.Summary.Should().Be("Scan completed.");
        returnedReceipt.ToolReceipts.Should().HaveCount(1);
    }

    [Fact]
    public async Task Test7_RetryJob_Returns200WithQueuedJob()
    {
        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = Guid.NewGuid(),
            Name = "Retry Target",
            BaseUrl = "https://retry.example.com",
            Enabled = true
        });

        var failedJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://retry.example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Failed,
            FailureReason = "TOOL_FAILED",
            RequestedByUserId = _adminUserId
        };

        _dbContext.SecurityScanJobs.Add(failedJob);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.RetryJob(failedJob.Id, default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var retriedJob = okResult.Value.Should().BeOfType<SecurityScanJob>().Subject;

        retriedJob.Status.Should().Be(SecurityScanJobStatus.Queued);
        retriedJob.RetryOfJobId.Should().Be(failedJob.Id);
        retriedJob.TargetUrl.Should().Be("https://retry.example.com");
    }

    [Fact]
    public async Task Test8_CancelJob_Returns200WithCancelledJob()
    {
        var runningJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = _adminUserId,
            Version = 1
        };

        _dbContext.SecurityScanJobs.Add(runningJob);
        await _dbContext.SaveChangesAsync();

        var request = new CancelScanJobApiRequest("User stopped scan", 1);
        var result = await _controller.CancelJob(runningJob.Id, request, default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var cancelledJob = okResult.Value.Should().BeOfType<SecurityScanJob>().Subject;

        cancelledJob.Status.Should().Be(SecurityScanJobStatus.Cancelled);
        cancelledJob.FailureReason.Should().Contain("User stopped scan");
    }

    [Fact]
    public async Task Test9_ListJobs_Returns200WithDetailDtoList()
    {
        var result = await _controller.ListJobs(page: 1, pageSize: 10, status: null, ct: default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var jobs = okResult.Value.Should().BeAssignableTo<IReadOnlyList<ScanJobDetailDto>>().Subject;

        jobs.Should().NotBeNull();
    }

    [Fact]
    public async Task Test10_TenantB_Cannot_Access_TenantA_Job_Returns403()
    {
        var tenantAUserId = Guid.NewGuid();
        var tenantBUserId = Guid.NewGuid();

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = tenantAUserId,
            Version = 1
        };

        _dbContext.SecurityScanJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        // Switch to Tenant B (non-admin)
        _mockUser.Setup(u => u.UserId).Returns(tenantBUserId);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        // 1. GetJob returns 403
        var getResult = await _controller.GetJob(job.Id, default);
        var getObjResult = getResult.Result.Should().BeOfType<ObjectResult>().Subject;
        getObjResult.StatusCode.Should().Be(403);

        // 2. CancelJob returns 403
        var cancelResult = await _controller.CancelJob(job.Id, new CancelScanJobApiRequest("Malicious cancel", 1), default);
        var cancelObjResult = cancelResult.Result.Should().BeOfType<ObjectResult>().Subject;
        cancelObjResult.StatusCode.Should().Be(403);

        // 3. RetryJob returns 403
        var retryResult = await _controller.RetryJob(job.Id, default);
        var retryObjResult = retryResult.Result.Should().BeOfType<ObjectResult>().Subject;
        retryObjResult.StatusCode.Should().Be(403);

        // 4. GetJobSummary returns 403
        var summaryResult = await _controller.GetJobSummary(job.Id, default);
        var summaryObjResult = summaryResult.Result.Should().BeOfType<ObjectResult>().Subject;
        summaryObjResult.StatusCode.Should().Be(403);

        // 5. GetJobDiff returns 403
        var diffResult = await _controller.GetJobDiff(job.Id, null, default);
        var diffObjResult = diffResult.Result.Should().BeOfType<ObjectResult>().Subject;
        diffObjResult.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task Test11_GetJobSummary_Returns200_WithAccurateMetrics()
    {
        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _adminUserId,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetJobSummary(job.Id, default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var summary = okResult.Value.Should().BeOfType<ScanResultSummary>().Subject;

        summary.ScanJobId.Should().Be(job.Id);
        summary.JobStatus.Should().Be(SecurityScanJobStatus.Completed);
    }

    [Fact]
    public async Task Test12_GetJobDiff_Returns200_WithDiffItems()
    {
        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _adminUserId,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetJobDiff(job.Id, null, default);
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var diff = okResult.Value.Should().BeOfType<ScanDiff>().Subject;

        diff.CurrentScanJobId.Should().Be(job.Id);
        diff.NewFindings.Should().NotBeNull();
    }
}
