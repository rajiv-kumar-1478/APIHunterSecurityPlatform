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
        health2.Status.Should().Be("NotConfigured");
        health2.Diagnostics.Should().Contain(d => d.Contains("not configured"));
    }

    [Fact]
    public async Task ScannerRuntimeHealth_EvaluatesAllStatusCategories_Accurately()
    {
        // 1. Healthy (Cloud Mode with valid 200 response & active gateway)
        var messageHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        using var httpClient = new HttpClient(messageHandler);

        var healthyOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = "SECRET_123",
            EgressGatewayEndpoint = "http://gateway.internal:8888",
            EnforceImageProvenance = true
        };

        var healthyService = new ScanToolHealthService(options: healthyOptions, egressGateway: _mockGateway.Object, httpClient: httpClient);
        var healthyHealth = await healthyService.GetScannerRuntimeHealthAsync();
        healthyHealth.Status.Should().Be("Healthy");
        healthyHealth.ReadyForScans.Should().BeTrue();
        healthyHealth.Diagnostics.Should().Contain(d => d.Contains("operational"));

        // 2. Unavailable (Cloud endpoint returning 500 error)
        var errHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var errHttpClient = new HttpClient(errHandler);

        var unavailService = new ScanToolHealthService(options: healthyOptions, egressGateway: _mockGateway.Object, httpClient: errHttpClient);
        var unavailHealth = await unavailService.GetScannerRuntimeHealthAsync();
        unavailHealth.Status.Should().Be("Unavailable");
        unavailHealth.ReadyForScans.Should().BeFalse();

        // 3. FailClosed (Image provenance disabled or gateway offline)
        var failGatewayMock = new Mock<IEnforcedEgressGateway>();
        failGatewayMock.Setup(g => g.IsGatewayHealthyAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var failClosedService = new ScanToolHealthService(options: healthyOptions, egressGateway: failGatewayMock.Object, httpClient: httpClient);
        var failClosedHealth = await failClosedService.GetScannerRuntimeHealthAsync();
        failClosedHealth.Status.Should().Be("FailClosed");
        failClosedHealth.ReadyForScans.Should().BeFalse();
        failClosedHealth.Diagnostics.Should().Contain(d => d.Contains("offline or unreachable"));

        // 4. Degraded (Unsafe local process fallback mode enabled in dev)
        var devDegradedOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.UnsafeLocalProcessFallback,
            AllowUnsafeProcessFallback = true,
            EnforceImageProvenance = true
        };
        var degradedService = new ScanToolHealthService(options: devDegradedOptions, egressGateway: _mockGateway.Object);
        var degradedHealth = await degradedService.GetScannerRuntimeHealthAsync();
        degradedHealth.Status.Should().Be("Degraded");
        degradedHealth.ReadyForScans.Should().BeFalse("Unsafe fallback mode must never report ReadyForScans=true in production dashboard");
        degradedHealth.Diagnostics.Should().Contain(d => d.Contains("unsafe local process mode"));
    }

    private class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string? _content;

        public FakeHttpMessageHandler(HttpStatusCode statusCode, string? content = null)
        {
            _statusCode = statusCode;
            _content = content;
        }

        public FakeHttpMessageHandler(HttpResponseMessage response)
        {
            _statusCode = response.StatusCode;
            _content = response.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode);
            if (_content != null)
            {
                response.Content = new StringContent(_content);
            }
            return Task.FromResult(response);
        }
    }
}
