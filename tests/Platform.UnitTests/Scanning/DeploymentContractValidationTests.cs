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
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

/// <summary>
/// Phase 8 Step 3B.5.1 Deployment Contract & Configuration Validation Suite.
/// Verifies configuration contracts across LocalDocker, Render Background Worker, and Railway Private Service architectures.
/// </summary>
public class DeploymentContractValidationTests
{
    private readonly Mock<IEnforcedEgressGateway> _mockGateway;

    public DeploymentContractValidationTests()
    {
        _mockGateway = new Mock<IEnforcedEgressGateway>();
        _mockGateway.Setup(g => g.IsGatewayHealthyAsync(It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
    }

    [Fact]
    public void LocalDocker_ConfigurationContract_BindsCorrectly()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            ["ScannerRuntime:RuntimeMode"] = "LocalDocker",
            ["ScannerRuntime:EgressGatewayMode"] = "EnforcedGateway",
            ["ScannerRuntime:EgressNetworkName"] = "apihunter-sandbox-net",
            ["ScannerRuntime:EgressGatewayEndpoint"] = "http://127.0.0.1:8888",
            ["ScannerRuntime:MaxCpuCores"] = "2.5",
            ["ScannerRuntime:MaxMemoryBytes"] = "2147483648", // 2 GiB
            ["ScannerRuntime:MaxPids"] = "150",
            ["ScannerRuntime:EnforceImageProvenance"] = "true"
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

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
        options.AllowUnsafeProcessFallback.Should().BeFalse("Unsafe process fallback must default to false");
    }

    [Fact]
    public void CloudManagedContainer_ConfigurationContract_BindsEnvironmentVariables_AndPreservesSecretIntegrity()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            ["ScannerRuntime:RuntimeMode"] = "CloudManagedContainer",
            ["ScannerRuntime:EgressGatewayMode"] = "EnforcedGateway",
            ["ScannerRuntime:EgressGatewayEndpoint"] = "http://egress-gateway.internal:8888",
            ["ScannerRuntime:HostedScannerServiceEndpoint"] = "http://scanner-worker.railway.internal:8080",
            ["ScannerRuntime:HostedScannerServiceKey"] = "SECRET_ENV_SCANNER_KEY_XYZ_999",
            ["ScannerRuntime:EnforceImageProvenance"] = "true"
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var options = config.GetSection("ScannerRuntime").Get<ScannerRuntimeOptions>();

        options.Should().NotBeNull();
        options!.RuntimeMode.Should().Be(ScannerRuntimeMode.CloudManagedContainer);
        options.HostedScannerServiceEndpoint.Should().Be("http://scanner-worker.railway.internal:8080");
        options.HostedScannerServiceKey.Should().Be("SECRET_ENV_SCANNER_KEY_XYZ_999");
        options.EgressGatewayEndpoint.Should().Be("http://egress-gateway.internal:8888");
    }

    [Fact]
    public async Task CloudManagedContainer_HealthDto_NeverExposesSecretKey_InPlaintext()
    {
        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = "SUPER_SECRET_AUTHENTICATION_KEY_DO_NOT_LEAK",
            EgressGatewayEndpoint = "http://egress-gateway.internal:8888"
        };

        var messageHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        using var httpClient = new HttpClient(messageHandler);

        var healthService = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: options,
            egressGateway: _mockGateway.Object,
            httpClient: httpClient);

        var health = await healthService.GetScannerRuntimeHealthAsync();

        health.Should().NotBeNull();
        health.ReadyForScans.Should().BeTrue();

        // Serialize to JSON as returned by API controller
        var json = JsonSerializer.Serialize(health);

        json.Should().NotContain("SUPER_SECRET_AUTHENTICATION_KEY_DO_NOT_LEAK", "Raw service key must NEVER be serialized or exposed in health DTOs");
    }

    [Fact]
    public async Task CloudManagedContainer_MissingSecretKey_OrEndpoint_SetsReadyForScansToFalse()
    {
        // 1. Missing Secret Key
        var missingKeyOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = null
        };

        var healthServiceMissingKey = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: missingKeyOptions,
            egressGateway: _mockGateway.Object);

        var health1 = await healthServiceMissingKey.GetScannerRuntimeHealthAsync();
        health1.ReadyForScans.Should().BeFalse();
        health1.Runtime.Available.Should().BeFalse();

        // 2. Missing Endpoint
        var missingEndpointOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = null,
            HostedScannerServiceKey = "SECRET_KEY_123"
        };

        var healthServiceMissingEndpoint = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: missingEndpointOptions,
            egressGateway: _mockGateway.Object);

        var health2 = await healthServiceMissingEndpoint.GetScannerRuntimeHealthAsync();
        health2.ReadyForScans.Should().BeFalse();
        health2.Runtime.Available.Should().BeFalse();
    }

    private class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public FakeHttpMessageHandler(HttpResponseMessage response)
        {
            _response = response;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_response);
        }
    }
}
