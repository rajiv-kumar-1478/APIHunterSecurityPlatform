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

        _controller = new SecurityScanController(_scanJobService, _toolRegistryService, _toolHealthService, _secretStore);
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
}
