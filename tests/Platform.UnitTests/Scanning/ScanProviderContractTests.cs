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
    public void BugHunterProvider_ExposesStableProviderKey()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        provider.ProviderKey.Should().Be("bughunter");
    }

    [Fact]
    public async Task BugHunterProvider_StartAsync_FailsClosedWithoutAuthoritativeContract()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var request = new ScanExecutionRequest(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://example.com",
            Profile: SecurityScanProfileType.Recon,
            ProviderKey: "bughunter",
            Parameters: new Dictionary<string, string>(),
            Timeout: TimeSpan.FromMinutes(5));

        var result = await provider.StartAsync(request);

        result.Success.Should().BeFalse();
        result.ExternalScanId.Should().BeEmpty();
        result.ErrorMessage.Should().Be(BugHunterScanProvider.UnavailableCode);
    }

    [Fact]
    public async Task BugHunterProvider_Status_RemainsBlockedWithoutSyntheticProgress()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var status = await provider.GetStatusAsync("unverified-external-id");

        status.ExternalScanId.Should().Be("unverified-external-id");
        status.Status.Should().Be(SecurityScanJobStatus.Blocked);
        status.ProgressPercent.Should().Be(0);
        status.Message.Should().Be(BugHunterScanProvider.UnavailableCode);
    }

    [Fact]
    public async Task BugHunterProvider_Result_HasNoSyntheticToolsOrArtifacts()
    {
        var provider = new BugHunterScanProvider(NullLogger<BugHunterScanProvider>.Instance);
        var result = await provider.GetResultAsync("unverified-external-id");

        result.Status.Should().Be(SecurityScanJobStatus.Blocked);
        result.ToolResults.Should().BeEmpty();
        result.ArtifactReference.Should().BeNull();
        result.Summary.Should().Be(BugHunterScanProvider.UnavailableCode);
    }

    [Fact]
    public async Task InMemorySecretStore_ReportsDevelopmentCredentialsSeparatelyFromProviderAvailability()
    {
        var secretStore = new InMemoryScanProviderSecretStore();
        var status = await secretStore.GetStatusAsync("bughunter");

        status.ProviderKey.Should().Be("bughunter");
        status.Configured.Should().BeTrue();
        status.RequiredKeys.Should().Contain("GROQ_API_KEY");
    }

    [Fact]
    public async Task InMemorySecretStore_AcquireLease_ReturnsValidLease()
    {
        var secretStore = new InMemoryScanProviderSecretStore();
        using var lease = await secretStore.AcquireLeaseAsync("bughunter");

        lease.ProviderKey.Should().Be("bughunter");
        lease.Secrets.Should().ContainKey("GROQ_API_KEY");
        lease.ExpiresAtUtc.Should().BeAfter(DateTime.UtcNow);
    }
}
