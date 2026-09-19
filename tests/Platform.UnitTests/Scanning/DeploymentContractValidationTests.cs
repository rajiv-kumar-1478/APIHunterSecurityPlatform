using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class DeploymentContractValidationTests
{
    private readonly Mock<IEnforcedEgressGateway> _mockGateway;

    public DeploymentContractValidationTests()
    {
        _mockGateway = new Mock<IEnforcedEgressGateway>();
        _mockGateway
            .Setup(g => g.IsGatewayHealthyAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    [Fact]
    public void LocalDocker_ConfigurationContract_BindsCorrectly()
    {
        var settings = new Dictionary<string, string?>
        {
            ["ScannerRuntime:RuntimeMode"] = "LocalDocker",
            ["ScannerRuntime:EgressGatewayMode"] = "EnforcedGateway",
            ["ScannerRuntime:EgressNetworkName"] = "apihunter-sandbox-net",
            ["ScannerRuntime:EgressGatewayEndpoint"] = "http://127.0.0.1:8888",
            ["ScannerRuntime:MaxCpuCores"] = "2.5",
            ["ScannerRuntime:MaxMemoryBytes"] = "2147483648",
            ["ScannerRuntime:MaxPids"] = "150",
            ["ScannerRuntime:EnforceImageProvenance"] = "true"
        };

        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var options = config.GetSection("ScannerRuntime").Get<ScannerRuntimeOptions>();

        options.Should().NotBeNull();
        options!.RuntimeMode.Should().Be(ScannerRuntimeMode.LocalDocker);
        options.EgressGatewayMode.Should().Be(EgressGatewayMode.EnforcedGateway);
        options.EgressNetworkName.Should().Be("apihunter-sandbox-net");
        options.EgressGatewayEndpoint.Should().Be("http://127.0.0.1:8888");
        options.MaxCpuCores.Should().Be(2.5);
        options.MaxMemoryBytes.Should().Be(2147483648);
        options.MaxPids.Should().Be(150);
        options.EnforceImageProvenance.Should().BeTrue();
        options.AllowUnsafeProcessFallback.Should().BeFalse();
    }

    [Fact]
    public void CloudManagedContainer_ConfigurationContract_BindsEnvironmentVariables()
    {
        var settings = new Dictionary<string, string?>
        {
            ["ScannerRuntime:RuntimeMode"] = "CloudManagedContainer",
            ["ScannerRuntime:EgressGatewayMode"] = "EnforcedGateway",
            ["ScannerRuntime:EgressGatewayEndpoint"] = "http://egress-gateway.internal:8888",
            ["ScannerRuntime:HostedScannerServiceEndpoint"] = "http://scanner-worker.internal:8080",
            ["ScannerRuntime:HostedScannerServiceKey"] = "SECRET_ENV_SCANNER_KEY_XYZ_999",
            ["ScannerRuntime:EnforceImageProvenance"] = "true"
        };

        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var options = config.GetSection("ScannerRuntime").Get<ScannerRuntimeOptions>();

        options.Should().NotBeNull();
        options!.RuntimeMode.Should().Be(ScannerRuntimeMode.CloudManagedContainer);
        options.HostedScannerServiceEndpoint.Should().Be("http://scanner-worker.internal:8080");
        options.HostedScannerServiceKey.Should().Be("SECRET_ENV_SCANNER_KEY_XYZ_999");
        options.EgressGatewayEndpoint.Should().Be("http://egress-gateway.internal:8888");
    }

    [Fact]
    public async Task DisabledRuntime_HealthIsTruthfullyNotConfigured()
    {
        var healthService = new ScanToolHealthService(options: new ScannerRuntimeOptions());

        var health = await healthService.GetScannerRuntimeHealthAsync();

        health.Status.Should().Be("NotConfigured");
        health.Runtime.Mode.Should().Be(nameof(ScannerRuntimeMode.Disabled));
        health.Runtime.Available.Should().BeFalse();
        health.Sandbox.SandboxIsolated.Should().BeFalse();
        health.Sandbox.ProxyEnforced.Should().BeFalse();
        health.Egress.Enforced.Should().BeFalse();
        health.ReadyForScans.Should().BeFalse();
    }

    [Fact]
    public async Task ConfiguredGatewayUri_WithoutReadinessContract_DoesNotClaimHealthy()
    {
        var gateway = new EnforcedEgressGateway(
            Mock.Of<IEgressPolicyEngine>(),
            new ScannerRuntimeOptions
            {
                RuntimeMode = ScannerRuntimeMode.LocalDocker,
                EgressGatewayMode = EgressGatewayMode.EnforcedGateway,
                EgressGatewayEndpoint = "http://syntactically-valid.invalid:8888"
            },
            NullLogger<EnforcedEgressGateway>.Instance);

        (await gateway.IsGatewayHealthyAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task CloudManagedContainer_HealthDto_NeverExposesSecretKey_InPlaintext()
    {
        var options = CreateHealthyCloudOptions("SUPER_SECRET_AUTHENTICATION_KEY_DO_NOT_LEAK");
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK));
        var healthService = new ScanToolHealthService(
            options: options,
            egressGateway: _mockGateway.Object,
            httpClient: httpClient);

        var health = await healthService.GetScannerRuntimeHealthAsync();

        health.ReadyForScans.Should().BeTrue();
        JsonSerializer.Serialize(health).Should().NotContain(
            "SUPER_SECRET_AUTHENTICATION_KEY_DO_NOT_LEAK",
            "raw service keys must never be serialized in health responses");
    }

    [Fact]
    public async Task CloudManagedContainer_MissingSecretKeyOrEndpoint_IsNotReady()
    {
        var missingKey = CreateHealthyCloudOptions(serviceKey: null);
        var missingKeyHealth = await new ScanToolHealthService(
            options: missingKey,
            egressGateway: _mockGateway.Object).GetScannerRuntimeHealthAsync();

        missingKeyHealth.ReadyForScans.Should().BeFalse();
        missingKeyHealth.Runtime.Available.Should().BeFalse();

        var missingEndpoint = CreateHealthyCloudOptions("SECRET_KEY_123") with
        {
            HostedScannerServiceEndpoint = null
        };
        var missingEndpointHealth = await new ScanToolHealthService(
            options: missingEndpoint,
            egressGateway: _mockGateway.Object).GetScannerRuntimeHealthAsync();

        missingEndpointHealth.Status.Should().Be("NotConfigured");
        missingEndpointHealth.ReadyForScans.Should().BeFalse();
        missingEndpointHealth.Diagnostics.Should().Contain(d => d.Contains("not configured"));
    }

    [Fact]
    public async Task ScannerRuntimeHealth_EvaluatesOperationalUnavailableAndFailClosedStates()
    {
        var options = CreateHealthyCloudOptions("SECRET_123");
        using var healthyClient = new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK));
        var healthy = await new ScanToolHealthService(
            options: options,
            egressGateway: _mockGateway.Object,
            httpClient: healthyClient).GetScannerRuntimeHealthAsync();

        healthy.Status.Should().Be("Healthy");
        healthy.ReadyForScans.Should().BeTrue();
        healthy.Diagnostics.Should().Contain(d => d.Contains("operational"));

        using var failedClient = new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.InternalServerError));
        var unavailable = await new ScanToolHealthService(
            options: options,
            egressGateway: _mockGateway.Object,
            httpClient: failedClient).GetScannerRuntimeHealthAsync();

        unavailable.Status.Should().Be("Unavailable");
        unavailable.ReadyForScans.Should().BeFalse();

        var failedGateway = new Mock<IEnforcedEgressGateway>();
        failedGateway
            .Setup(g => g.IsGatewayHealthyAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        var failClosed = await new ScanToolHealthService(
            options: options,
            egressGateway: failedGateway.Object,
            httpClient: healthyClient).GetScannerRuntimeHealthAsync();

        failClosed.Status.Should().Be("FailClosed");
        failClosed.ReadyForScans.Should().BeFalse();
        failClosed.Diagnostics.Should().Contain(d => d.Contains("could not be verified"));
    }

    [Fact]
    public async Task UnsafeLocalProcessMode_IsDegradedAndNeverReady()
    {
        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.UnsafeLocalProcessFallback,
            EgressGatewayMode = EgressGatewayMode.EnforcedGateway,
            EgressGatewayEndpoint = "http://gateway.internal:8888",
            AllowUnsafeProcessFallback = true,
            EnforceImageProvenance = true
        };

        var health = await new ScanToolHealthService(
            options: options,
            egressGateway: _mockGateway.Object).GetScannerRuntimeHealthAsync();

        health.Status.Should().Be("Degraded");
        health.ReadyForScans.Should().BeFalse();
        health.Diagnostics.Should().Contain(d => d.Contains("unsafe local process mode"));
    }

    private static ScannerRuntimeOptions CreateHealthyCloudOptions(string? serviceKey) => new()
    {
        RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
        EgressGatewayMode = EgressGatewayMode.EnforcedGateway,
        EgressGatewayEndpoint = "http://egress-gateway.internal:8888",
        HostedScannerServiceEndpoint = "https://scanner.internal",
        HostedScannerServiceKey = serviceKey,
        EnforceImageProvenance = true
    };

    private sealed class FakeHttpMessageHandler(HttpStatusCode statusCode) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode));
    }
}
