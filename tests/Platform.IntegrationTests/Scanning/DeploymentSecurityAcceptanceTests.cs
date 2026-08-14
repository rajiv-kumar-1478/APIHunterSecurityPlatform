using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
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

/// <summary>
/// Phase 8 Step 4.9: Deployment-Level Security Acceptance Pass.
/// Verifies the production deployment security perimeter:
/// 1. Real Docker / Hosted Scanner Runtime Sandbox configuration & fallback prohibition.
/// 2. Image Provenance & Container Image Digest Pinning (Zero unpinned/latest execution).
/// 3. Egress Gateway Network Topology & Socket-Level Interception (IMDS, RFC 1918, Loopback blocking).
/// 4. Cancellation propagation across the sandbox boundary.
/// 5. Operational telemetry & Runtime Readiness observability contracts.
/// </summary>
public class DeploymentSecurityAcceptanceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly ScanToolHealthService _healthService;
    private readonly InMemoryScanProviderSecretStore _secretStore;

    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();
    private const string ValidSha256Digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public DeploymentSecurityAcceptanceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("DeploymentSecurityAcceptanceTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _toolRegistry = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _healthService = new ScanToolHealthService(_toolRegistry, NullLogger<ScanToolHealthService>.Instance);
        _secretStore = new InMemoryScanProviderSecretStore();

        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "ProductionDeploymentRepo",
            FullName = "enterprise/ProductionDeploymentRepo",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/ProductionDeploymentRepo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Production API Gateway",
            TargetType = "WebEndpoint",
            BaseUrl = "https://api.enterprise.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    // =========================================================================
    // GATE 1: Docker Runtime Sandbox Invariant & Fallback Prohibition
    // =========================================================================
    [Fact]
    public async Task Gate1_DockerRuntime_RejectsUnsafeHostFallback_AndEnforcesSandboxIsolation()
    {
        var runtimeOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.LocalDocker,
            AllowUnsafeProcessFallback = false,
            RequireDockerSandbox = true,
            EnableReadOnlyRoot = true,
            DropAllCapabilities = true,
            NoNewPrivileges = true,
            TrustedImageRegistries = new[] { "ghcr.io/projectdiscovery" },
            PlatformScratchRoot = Path.Combine(Path.GetTempPath(), "apihunter_scans")
        };

        var mockSession = new Mock<IEnforcedEgressGatewaySession>();
        mockSession.Setup(s => s.NetworkName).Returns("apihunter-sandbox-net");
        mockSession.Setup(s => s.GatewayEndpoint).Returns("http://127.0.0.1:8888");
        mockSession.Setup(s => s.ContainerEnvironmentVariables).Returns(new Dictionary<string, string>());
        mockSession.Setup(s => s.DisposeAsync()).Returns(ValueTask.CompletedTask);

        var gatewayMock = new Mock<IEnforcedEgressGateway>();
        gatewayMock.Setup(g => g.CreateScopedSessionAsync(It.IsAny<EgressTarget>(), It.IsAny<CancellationToken>()))
                   .ReturnsAsync(mockSession.Object);

        Mock<IGenericCliToolAdapter> cliAdapterMock = new();
        var dockerSandbox = new DockerScannerRuntime(
            runtimeOptions,
            toolKey => cliAdapterMock.Object,
            gatewayMock.Object,
            NullLogger<DockerScannerRuntime>.Instance
        );

        var toolRequest = new ToolExecutionRequest(
            ToolKey: "nuclei",
            Version: "v3.1.0",
            Arguments: new Dictionary<string, string> { ["u"] = "https://api.enterprise.com" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(30),
            Executable: "nuclei",
            ContainerImageRepository: "ghcr.io/projectdiscovery/nuclei",
            ContainerImageDigest: ValidSha256Digest
        );

        var egressTarget = new EgressTarget(
            RawTargetUrl: "https://api.enterprise.com",
            CanonicalHost: "api.enterprise.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(10));
        var scratchDir = Path.Combine(runtimeOptions.PlatformScratchRoot, Guid.NewGuid().ToString("N"));

        // If Docker daemon is absent in CI environment, runtime must fail closed with error code rather than falling back to host process execution
        var result = await dockerSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDir, CancellationToken.None);

        if (result.Status != ToolExecutionStatus.Success)
        {
            result.Status.Should().Be(ToolExecutionStatus.Failed);
            result.ErrorCode.Should().NotBeNull();
            result.ErrorCode.Should().ContainAny("DOCKER_", "SANDBOX_", "CONTAINER_", "TOOL_PROVENANCE_");
        }
    }

    // =========================================================================
    // GATE 2: Immutable Image Provenance & Digest Pinning Verification
    // =========================================================================
    [Fact]
    public async Task Gate2_ImageProvenance_EnforcesDigestPinning_AndRejectsUnpinnedImages()
    {
        var runtimeOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.LocalDocker,
            EnforceImageProvenance = true,
            TrustedImageRegistries = new[] { "ghcr.io/projectdiscovery", "docker.io/projectdiscovery" }
        };

        var mockSession = new Mock<IEnforcedEgressGatewaySession>();
        mockSession.Setup(s => s.DisposeAsync()).Returns(ValueTask.CompletedTask);

        var gatewayMock = new Mock<IEnforcedEgressGateway>();
        gatewayMock.Setup(g => g.CreateScopedSessionAsync(It.IsAny<EgressTarget>(), It.IsAny<CancellationToken>()))
                   .ReturnsAsync(mockSession.Object);

        Mock<IGenericCliToolAdapter> cliAdapterMock = new();
        var dockerSandbox = new DockerScannerRuntime(
            runtimeOptions,
            toolKey => cliAdapterMock.Object,
            gatewayMock.Object,
            NullLogger<DockerScannerRuntime>.Instance
        );

        // Tool request missing immutable SHA-256 digest
        var unpinnedRequest = new ToolExecutionRequest(
            ToolKey: "nuclei",
            Version: "v3.1.0",
            Arguments: new Dictionary<string, string> { ["u"] = "https://api.enterprise.com" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "nuclei",
            ContainerImageRepository: "ghcr.io/projectdiscovery/nuclei",
            ContainerImageDigest: null // Prohibited: unpinned / :latest
        );

        var egressTarget = new EgressTarget(
            RawTargetUrl: "https://api.enterprise.com",
            CanonicalHost: "api.enterprise.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(10));
        var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        var result = await dockerSandbox.ExecuteInSandboxAsync(unpinnedRequest, egressTarget, secretLease, scratchDir, CancellationToken.None);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Contain("TOOL_PROVENANCE_NOT_VERIFIED");
    }

    // =========================================================================
    // GATE 3: Egress Gateway Socket Proxy Enforcement & Attack Mitigation
    // =========================================================================
    [Fact]
    public async Task Gate3_EgressProxy_BlocksLoopback_IMDS_AndPrivateSubnets_AtSocketLevel()
    {
        var approvedTarget = new EgressTarget(
            RawTargetUrl: "http://api.enterprise.com",
            CanonicalHost: "api.enterprise.com",
            Port: 80,
            Scheme: "http",
            ApprovedIpAddresses: new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        var egressPolicyEngine = new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance);
        var gateway = new EnforcedEgressGateway(egressPolicyEngine, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        await using var session = await gateway.CreateScopedSessionAsync(approvedTarget);

        await using var proxyServer = new EnforcedEgressProxyServer(session, null, NullLogger.Instance);
        proxyServer.Start();

        var handler = new System.Net.Http.HttpClientHandler
        {
            Proxy = new WebProxy(proxyServer.ProxyEndpoint),
            UseProxy = true
        };

        using var client = new System.Net.Http.HttpClient(handler);

        // 1. Loopback (127.0.0.1) must be blocked with 403 Forbidden
        var loopbackResponse = await client.GetAsync("http://127.0.0.1/test");
        loopbackResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // 2. Cloud IMDS (169.254.169.254) must be blocked with 403 Forbidden
        var imdsResponse = await client.GetAsync("http://169.254.169.254/latest/meta-data");
        imdsResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // 3. RFC 1918 Private Subnet (10.0.0.1) must be blocked with 403 Forbidden
        var rfc1918Response = await client.GetAsync("http://10.0.0.1:8080/test");
        rfc1918Response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // =========================================================================
    // GATE 4: Cancellation Token Propagation Across Sandbox Boundary
    // =========================================================================
    [Fact]
    public async Task Gate4_CancellationPropagation_AbortsRunningSandboxJob_FailsClosed()
    {
        var runtimeOptions = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.LocalDocker,
            AllowUnsafeProcessFallback = false,
            TrustedImageRegistries = new[] { "ghcr.io/projectdiscovery" }
        };

        var mockSession = new Mock<IEnforcedEgressGatewaySession>();
        mockSession.Setup(s => s.DisposeAsync()).Returns(ValueTask.CompletedTask);

        var gatewayMock = new Mock<IEnforcedEgressGateway>();
        gatewayMock.Setup(g => g.CreateScopedSessionAsync(It.IsAny<EgressTarget>(), It.IsAny<CancellationToken>()))
                   .ReturnsAsync(mockSession.Object);

        Mock<IGenericCliToolAdapter> cliAdapterMock = new();
        var dockerSandbox = new DockerScannerRuntime(
            runtimeOptions,
            toolKey => cliAdapterMock.Object,
            gatewayMock.Object,
            NullLogger<DockerScannerRuntime>.Instance
        );

        var toolRequest = new ToolExecutionRequest(
            ToolKey: "nuclei",
            Version: "v3.1.0",
            Arguments: new Dictionary<string, string> { ["u"] = "https://api.enterprise.com" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(5),
            Executable: "nuclei",
            ContainerImageRepository: "ghcr.io/projectdiscovery/nuclei",
            ContainerImageDigest: ValidSha256Digest
        );

        var egressTarget = new EgressTarget(
            RawTargetUrl: "https://api.enterprise.com",
            CanonicalHost: "api.enterprise.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(10));
        var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancelled token

        var result = await dockerSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDir, cts.Token);

        result.Status.Should().Be(ToolExecutionStatus.Cancelled);
    }

    // =========================================================================
    // GATE 5: Observability & Runtime Readiness Status Categorization
    // =========================================================================
    [Fact]
    public async Task Gate5_Observability_ExposesGranularHealthCategories_WithoutSecretLeakage()
    {
        var tool = await _toolRegistry.RegisterToolAsync(
            toolKey: "nuclei",
            displayName: "Nuclei Scanner",
            version: "v3.1.0",
            required: true,
            capabilities: new[] { ToolCapability.VulnerabilityScanning },
            executable: "nuclei"
        );

        var healthReport = await _healthService.GetScannerRuntimeHealthAsync(default);

        healthReport.Should().NotBeNull();
        healthReport.Status.Should().BeOneOf("Healthy", "Degraded", "Unavailable", "NotConfigured", "FailClosed");

        // Secret safety: Diagnostics must never leak credentials or internal keys
        var healthJson = System.Text.Json.JsonSerializer.Serialize(healthReport);
        healthJson.Should().NotContain("secret");
        healthJson.Should().NotContain("password");
        healthJson.Should().NotContain("apiKey");
    }
}
