using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanProviderContractTests
{
    [Fact]
    public void Test1_BugHunterProvider_ExposesCorrectProviderKey()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        provider.ProviderKey.Should().Be("bughunter");
    }

    [Fact]
    public async Task Test2_BugHunterProvider_StartAsync_ReturnsValidExternalScanId()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var request = new ScanExecutionRequest(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://example.com",
            Profile: SecurityScanProfileType.Recon,
            ProviderKey: "bughunter",
            Parameters: new Dictionary<string, string>(),
            Timeout: TimeSpan.FromMinutes(5)
        );

        var result = await provider.StartAsync(request);

        result.Success.Should().BeTrue();
        result.ExternalScanId.Should().StartWith("bughunter-scan-");
    }

    [Fact]
    public async Task Test3_BugHunterProvider_GetStatusAsync_ReturnsRunningStatus()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var status = await provider.GetStatusAsync("bughunter-scan-123");

        status.ExternalScanId.Should().Be("bughunter-scan-123");
        status.Status.Should().Be(SecurityScanJobStatus.Running);
    }

    [Fact]
    public async Task Test4_BugHunterProvider_GetResultAsync_ReturnsToolExecutionResults()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var result = await provider.GetResultAsync("bughunter-scan-123");

        result.ExternalScanId.Should().Be("bughunter-scan-123");
        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        result.ToolResults.Should().NotBeEmpty();
        result.ToolResults.Should().Contain(t => t.ToolKey == "subfinder");
        result.ToolResults.Should().Contain(t => t.ToolKey == "httpx");
    }

    [Fact]
    public async Task Test5_InMemorySecretStore_DevTestOnly_ProvidesDefaultStatus()
    {
        var secretStore = new InMemoryScanProviderSecretStore();
        var status = await secretStore.GetStatusAsync("bughunter");

        status.ProviderKey.Should().Be("bughunter");
        status.Configured.Should().BeTrue();
        status.RequiredKeys.Should().Contain("GROQ_API_KEY");
    }

    [Fact]
    public async Task Test6_InMemorySecretStore_AcquireLease_ReturnsValidLease()
    {
        var secretStore = new InMemoryScanProviderSecretStore();
        using var lease = await secretStore.AcquireLeaseAsync("bughunter");

        lease.ProviderKey.Should().Be("bughunter");
        lease.Secrets.Should().ContainKey("GROQ_API_KEY");
        lease.ExpiresAtUtc.Should().BeAfter(DateTime.UtcNow);
    }
}
