using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public sealed class UnavailableScannerRuntimeTests
{
    [Fact]
    public async Task ExecuteInSandboxAsync_AlwaysFailsClosedWithoutProducingArtifact()
    {
        var runtime = new UnavailableScannerRuntime(
            NullLogger<UnavailableScannerRuntime>.Instance);
        var request = new ToolExecutionRequest(
            "test-tool",
            "1.0.0",
            new Dictionary<string, string>(),
            Guid.NewGuid(),
            TimeSpan.FromMinutes(1));
        var target = new EgressTarget(
            "https://example.com",
            "example.com",
            443,
            "https",
            new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(5),
            "test-v1");
        using var lease = new ProviderSecretLease(
            "test-provider",
            new Dictionary<string, string>(),
            TimeSpan.FromMinutes(1));

        var result = await runtime.ExecuteInSandboxAsync(
            request,
            target,
            lease,
            Path.GetTempPath());

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be(UnavailableScannerRuntime.ErrorCode);
        result.FailureClassification.Should().Be(ToolFailureClassification.SecurityBoundary);
        result.ArtifactReference.Should().BeNull();
    }
}
