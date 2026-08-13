using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Common;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class ScanJobServiceTests
{
    private class TestUserContext : ICurrentUserContext
    {
        public Guid? UserId { get; set; } = Guid.Parse("ade4b0fc-dd14-498d-af34-2d7151b8a142");
        public string? SessionId { get; set; } = "session-123";
        public bool IsAuthenticated { get; set; } = true;
        public bool IsPlatformAdmin { get; set; } = true;
        public string CorrelationId { get; set; } = "correlation-123";
        public string IpAddress { get; set; } = "127.0.0.1";
    }

    private PlatformDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(options);
    }

    [Fact]
    public async Task Test1_CreateScanJob_Succeeds_ForAuthorizedTarget()
    {
        var db = CreateDbContext();
        var targetId = Guid.NewGuid();
        db.SecurityTargets.Add(new SecurityTarget
        {
            Id = targetId,
            Name = "Production Web Target",
            BaseUrl = "https://example.com",
            Enabled = true
        });

        // Seed tool registry with healthy tools
        db.SecurityScanTools.Add(new SecurityScanTool
        {
            Id = Guid.NewGuid(),
            ToolKey = "subfinder",
            DisplayName = "Subfinder",
            Version = "v2.14.0",
            Required = true,
            Enabled = true,
            CapabilitiesJson = "[\"SubdomainEnumeration\"]",
            HealthStatus = ToolHealthStatus.Healthy
        });
        db.SecurityScanTools.Add(new SecurityScanTool
        {
            Id = Guid.NewGuid(),
            ToolKey = "httpx",
            DisplayName = "HTTPX",
            Version = "v1.6.0",
            Required = true,
            Enabled = true,
            CapabilitiesJson = "[\"HttpProbing\",\"DnsResolution\"]",
            HealthStatus = ToolHealthStatus.Healthy
        });
        await db.SaveChangesAsync();

        var userContext = new TestUserContext();
        var toolRegistry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        var service = new ScanJobService(db, userContext, toolRegistry, NullLogger<ScanJobService>.Instance);

        var request = new CreateScanJobRequest(
            RepositoryId: null,
            TargetId: targetId,
            TargetUrl: "https://example.com",
            ScanProfile: SecurityScanProfileType.Recon,
            ProviderKey: "bughunter"
        );

        var job = await service.CreateScanJobAsync(request);

        job.Should().NotBeNull();
        job.TargetUrl.Should().Be("https://example.com");
        job.Status.Should().Be(SecurityScanJobStatus.Queued);
        job.Version.Should().Be(1);
    }

    [Fact]
    public async Task Test2_CreateScanJob_Throws_WhenTargetIsOutOfScope()
    {
        var db = CreateDbContext();
        db.SecurityTargets.Add(new SecurityTarget
        {
            Id = Guid.NewGuid(),
            Name = "Authorized Target Only",
            BaseUrl = "https://authorized.com",
            Enabled = true
        });
        await db.SaveChangesAsync();

        var userContext = new TestUserContext();
        var toolRegistry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        var service = new ScanJobService(db, userContext, toolRegistry, NullLogger<ScanJobService>.Instance);

        var request = new CreateScanJobRequest(
            RepositoryId: null,
            TargetId: null,
            TargetUrl: "https://unauthorized-evil.com",
            ScanProfile: SecurityScanProfileType.Recon,
            ProviderKey: "bughunter"
        );

        var act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*out of scope*");
    }

    [Fact]
    public async Task Test3_CancelScanJob_Succeeds_AndIncrementsVersion()
    {
        var db = CreateDbContext();
        var jobId = Guid.NewGuid();
        db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "https://example.com",
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = Guid.Parse("ade4b0fc-dd14-498d-af34-2d7151b8a142"),
            Version = 1
        });
        await db.SaveChangesAsync();

        var userContext = new TestUserContext();
        var toolRegistry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        var service = new ScanJobService(db, userContext, toolRegistry, NullLogger<ScanJobService>.Instance);

        var job = await service.CancelScanJobAsync(jobId, "User requested cancellation", 1);

        job.Status.Should().Be(SecurityScanJobStatus.Cancelled);
        job.Version.Should().Be(2);
        job.CancelledAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task Test4_CancelScanJob_Throws_OnStaleVersion()
    {
        var db = CreateDbContext();
        var jobId = Guid.NewGuid();
        db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "https://example.com",
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = Guid.Parse("ade4b0fc-dd14-498d-af34-2d7151b8a142"),
            Version = 2
        });
        await db.SaveChangesAsync();

        var userContext = new TestUserContext();
        var toolRegistry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        var service = new ScanJobService(db, userContext, toolRegistry, NullLogger<ScanJobService>.Instance);

        var act = async () => await service.CancelScanJobAsync(jobId, "User requested cancellation", 1);
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>();
    }
}
