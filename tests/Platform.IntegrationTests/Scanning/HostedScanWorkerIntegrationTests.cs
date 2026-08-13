using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Common;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.IntegrationTests.Scanning;

public class HostedScanWorkerIntegrationTests
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

    [Fact]
    public async Task HostedScanJob_UsesRegisteredToolExecutable()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Authorized Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("amass", "Amass Scanner", "v4.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing });

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        var executedExecutable = string.Empty;
        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .Callback<ToolExecutionRequest, ProviderSecretLease, string, CancellationToken>((req, _, _, _) => executedExecutable = req.Executable ?? req.ToolKey)
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v4.0.0", ToolExecutionStatus.Success, 0, null, null));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, factory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(job.Id);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        executedExecutable.Should().Be("amass");
    }

    [Fact]
    public async Task HostedScanJob_RejectsUnregisteredExecutable()
    {
        Action act = () => GenericCliToolAdapter.ValidateToolExecutableWhitelist("unregistered_attacker_tool");
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*is not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task HostedScanJob_RejectsOutOfScopeTarget()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Authorized Target", BaseUrl = "https://authorized.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://unauthorized-evil.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>()
           .WithMessage("*out of scope*");
    }

    [Fact]
    public async Task HostedScanJob_CleansScratchDirectoryAfterExecution()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("subfinder", "Subfinder Tool", "v2.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing });

        var jobId = Guid.NewGuid();
        var job = new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        string createdScratchDir = string.Empty;
        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .Callback<ToolExecutionRequest, ProviderSecretLease, string, CancellationToken>((_, _, scratch, _) => createdScratchDir = scratch)
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v2.0.0", ToolExecutionStatus.Success, 0, null, null));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, factory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(jobId);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        createdScratchDir.Should().NotBeNullOrEmpty();
        Directory.Exists(createdScratchDir).Should().BeFalse("Worker must clean up scratch directory after execution");
    }

    [Fact]
    public async Task HostedScanJob_CancelsAndKillsProcessTree()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("subfinder", "Subfinder Tool", "v2.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing });

        var jobId = Guid.NewGuid();
        var job = new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v2.0.0", ToolExecutionStatus.TimedOut, 124, null, "CANCELLED"));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, factory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(jobId, cts.Token);

        result.Status.Should().Be(SecurityScanJobStatus.Failed);
        result.FailureReason.Should().Contain("CANCELLED");
    }

    private static PlatformDbContext CreateInMemoryDbContext()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(dbOptions);
    }
}
