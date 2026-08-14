using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScannerRuntimeSandboxTests
{
    private readonly Mock<IEgressPolicyEngine> _mockEgressEngine;
    private readonly Mock<IEgressNetworkProxy> _mockEgressProxy;
    private readonly EgressTarget _validEgressTarget;
    private readonly EgressTarget _expiredEgressTarget;

    public ScannerRuntimeSandboxTests()
    {
        _mockEgressEngine = new Mock<IEgressPolicyEngine>();
        _mockEgressProxy = new Mock<IEgressNetworkProxy>();

        _validEgressTarget = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<System.Net.IPAddress> { System.Net.IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0");

        _expiredEgressTarget = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<System.Net.IPAddress> { System.Net.IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow.AddMinutes(-30),
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(-10),
            PolicyVersion: "v1.0");

        var mockHandle = new Mock<IAsyncDisposable>();
        mockHandle.Setup(h => h.DisposeAsync()).Returns(ValueTask.CompletedTask);

        _mockEgressProxy
            .Setup(p => p.CreateScopedPolicyAsync(It.IsAny<EgressTarget>(), It.IsAny<System.Threading.CancellationToken>()))
            .ReturnsAsync(mockHandle.Object);
    }

    [Fact]
    public void DockerScannerRuntime_BuildsRequiredIsolationArguments()
    {
        var options = new ScannerRuntimeOptions
        {
            MaxCpuCores = 2.0,
            MaxMemoryBytes = 1_073_741_824,
            MaxPids = 100,
            EnableReadOnlyRoot = true,
            DropAllCapabilities = true,
            NoNewPrivileges = true
        };

        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new DockerScannerRuntime(options, toolKey => mockAdapter.Object, _mockEgressProxy.Object, NullLogger<DockerScannerRuntime>.Instance);

        var request = new ToolExecutionRequest("subfinder", "v2.6.6", new Dictionary<string, string>(), Guid.NewGuid(), TimeSpan.FromMinutes(10));
        var args = runtime.BuildDockerIsolationArguments(request, _validEgressTarget, Path.GetTempPath());

        args.Should().Contain("--read-only");
        args.Should().Contain("--cap-drop=ALL");
        args.Should().Contain("--security-opt=no-new-privileges:true");
        args.Should().Contain("--cpus=2");
        args.Should().Contain("--memory=1073741824");
        args.Should().Contain("--pids-limit=100");
    }

    [Fact]
    public async Task DockerScannerRuntime_RejectsExpiredEgressTarget()
    {
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new DockerScannerRuntime(new ScannerRuntimeOptions(), toolKey => mockAdapter.Object, _mockEgressProxy.Object, NullLogger<DockerScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest("subfinder", "v2.6.6", new Dictionary<string, string>(), Guid.NewGuid(), TimeSpan.FromMinutes(10));
        var result = await runtime.ExecuteInSandboxAsync(request, _expiredEgressTarget, secretLease, Path.GetTempPath());

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("EXPIRED_EGRESS_AUTHORIZATION");
    }

    [Fact]
    public async Task HostedScannerRuntime_RejectsMissingServiceAuthenticationKey()
    {
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        using var httpClient = new HttpClient();
        var runtime = new HostedScannerRuntime(httpClient, serviceKey: null, toolKey => mockAdapter.Object, _mockEgressProxy.Object, NullLogger<HostedScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest("subfinder", "v2.6.6", new Dictionary<string, string>(), Guid.NewGuid(), TimeSpan.FromMinutes(10));
        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, Path.GetTempPath());

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("MISSING_SERVICE_AUTHENTICATION_KEY");
    }

    [Fact]
    public async Task EgressNetworkProxy_ThrowsException_WhenTargetIsExpired()
    {
        var proxy = new EgressNetworkProxy(_mockEgressEngine.Object, NullLogger<EgressNetworkProxy>.Instance);
        Func<Task> act = async () => await proxy.CreateScopedPolicyAsync(_expiredEgressTarget);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*expired*");
    }

    [Fact]
    public async Task EgressNetworkProxy_Succeeds_ForValidTarget()
    {
        var proxy = new EgressNetworkProxy(_mockEgressEngine.Object, NullLogger<EgressNetworkProxy>.Instance);
        await using var handle = await proxy.CreateScopedPolicyAsync(_validEgressTarget);

        handle.Should().NotBeNull();
    }
}
