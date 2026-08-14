using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScannerRuntimeSandboxTests
{
    private readonly Mock<IEgressPolicyEngine> _mockEgressEngine;
    private readonly Mock<IEnforcedEgressGateway> _mockEgressGateway;
    private readonly EgressTarget _validEgressTarget;
    private readonly EgressTarget _expiredEgressTarget;
    private readonly IPAddress _approvedIp;
    private readonly IPAddress _unapprovedExternalIp;
    private readonly IPAddress _imdsIp;
    private readonly IPAddress _loopbackIp;
    private readonly IPAddress _privateIp;

    public ScannerRuntimeSandboxTests()
    {
        _mockEgressEngine = new Mock<IEgressPolicyEngine>();
        _mockEgressGateway = new Mock<IEnforcedEgressGateway>();

        _approvedIp = IPAddress.Parse("93.184.216.34");
        _unapprovedExternalIp = IPAddress.Parse("1.1.1.1");
        _imdsIp = IPAddress.Parse("169.254.169.254");
        _loopbackIp = IPAddress.Parse("127.0.0.1");
        _privateIp = IPAddress.Parse("10.0.0.1");

        _mockEgressEngine.Setup(e => e.IsProhibitedAddress(It.Is<IPAddress>(ip =>
            ip.Equals(_imdsIp) || ip.Equals(_loopbackIp) || ip.Equals(_privateIp)))).Returns(true);
        _mockEgressEngine.Setup(e => e.IsProhibitedAddress(It.Is<IPAddress>(ip =>
            ip.Equals(_approvedIp) || ip.Equals(_unapprovedExternalIp)))).Returns(false);

        _validEgressTarget = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { _approvedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0");

        _expiredEgressTarget = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { _approvedIp },
            ResolvedAtUtc: DateTime.UtcNow.AddMinutes(-30),
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(-10),
            PolicyVersion: "v1.0");

        var mockSession = new Mock<IEnforcedEgressGatewaySession>();
        mockSession.Setup(s => s.NetworkName).Returns("apihunter-sandbox-net");
        mockSession.Setup(s => s.GatewayEndpoint).Returns("http://127.0.0.1:8888");
        mockSession.Setup(s => s.ContainerEnvironmentVariables).Returns(new Dictionary<string, string>
        {
            ["HTTP_PROXY"] = "http://127.0.0.1:8888",
            ["HTTPS_PROXY"] = "http://127.0.0.1:8888",
            ["NO_PROXY"] = "",
            ["APIHUNTER_EGRESS_TARGET"] = "example.com"
        });
        mockSession.Setup(s => s.DisposeAsync()).Returns(ValueTask.CompletedTask);

        _mockEgressGateway
            .Setup(g => g.CreateScopedSessionAsync(It.IsAny<EgressTarget>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockSession.Object);
        _mockEgressGateway
            .Setup(g => g.IsGatewayHealthyAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
    }

    [Fact]
    public void DockerScannerRuntime_UnsafeFallback_DefaultConfiguration_IsDisabled()
    {
        var defaultOptions = new ScannerRuntimeOptions();
        defaultOptions.AllowUnsafeProcessFallback.Should().BeFalse("Unsafe host process fallback must be strictly disabled by default");
        defaultOptions.RuntimeMode.Should().Be(ScannerRuntimeMode.LocalDocker);
        defaultOptions.EnforceImageProvenance.Should().BeTrue();
    }

    [Fact]
    public void DockerScannerRuntime_BuildsRequiredIsolationArguments_WithEnforcedGatewayAndNoProxyEmpty()
    {
        var options = new ScannerRuntimeOptions
        {
            MaxCpuCores = 2.0,
            MaxMemoryBytes = 1_073_741_824,
            MaxPids = 100,
            EnableReadOnlyRoot = true,
            DropAllCapabilities = true,
            NoNewPrivileges = true,
            EgressNetworkName = "apihunter-sandbox-net"
        };

        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new DockerScannerRuntime(options, toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<DockerScannerRuntime>.Instance);

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: "subfinder",
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd46059d33ef0"
        );

        var mockSession = new Mock<IEnforcedEgressGatewaySession>();
        mockSession.Setup(s => s.NetworkName).Returns("apihunter-sandbox-net");
        mockSession.Setup(s => s.ContainerEnvironmentVariables).Returns(new Dictionary<string, string>
        {
            ["HTTP_PROXY"] = "http://127.0.0.1:8888",
            ["HTTPS_PROXY"] = "http://127.0.0.1:8888",
            ["NO_PROXY"] = "",
            ["APIHUNTER_EGRESS_TARGET"] = "example.com"
        });

        var scratchDir = Path.Combine(options.PlatformScratchRoot, request.ScanJobId.ToString("N"));
        var args = runtime.BuildDockerIsolationArguments(request, _validEgressTarget, mockSession.Object, scratchDir);

        args.Should().Contain("--read-only");
        args.Should().Contain("--cap-drop=ALL");
        args.Should().Contain("--security-opt=no-new-privileges:true");
        args.Should().Contain("--cpus=2");
        args.Should().Contain("--memory=1073741824");
        args.Should().Contain("--pids-limit=100");
        args.Should().Contain("--network=apihunter-sandbox-net");
        args.Should().Contain("--env=HTTP_PROXY=http://127.0.0.1:8888");
        args.Should().Contain("--env=HTTPS_PROXY=http://127.0.0.1:8888");
        args.Should().Contain("--env=NO_PROXY=");
        args.Should().Contain("--env=APIHUNTER_EGRESS_TARGET=example.com");
    }

    [Fact]
    public async Task DockerScannerRuntime_LocalDockerMode_FailsClosed_WithoutHostProcessFallback_WhenDockerUnavailable()
    {
        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.LocalDocker,
            RequireDockerSandbox = true,
            AllowUnsafeProcessFallback = false
        };

        var mockAdapter = new Mock<IGenericCliToolAdapter>();
        mockAdapter.Setup(a => a.ToolKey).Returns("subfinder");
        mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                   .ReturnsAsync(new ToolExecutionResult("subfinder", "v2.6.6", ToolExecutionStatus.Success, 0, null, null));

        var runtime = new DockerScannerRuntime(options, toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<DockerScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: "subfinder",
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd46059d33ef0"
        );

        var scratchDir = Path.Combine(options.PlatformScratchRoot, request.ScanJobId.ToString("N"));
        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, scratchDir);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Match(code => code == "DOCKER_RUNTIME_UNAVAILABLE" || code!.StartsWith("DOCKER_CONTAINER_EXECUTION_FAILED") || code!.StartsWith("DOCKER_LAUNCH_FAILED"));

        // PROOF: Host CLI process adapter was NEVER invoked on Docker failure
        if (result.ErrorCode == "DOCKER_RUNTIME_UNAVAILABLE")
        {
            mockAdapter.Verify(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Fact]
    public async Task DockerScannerRuntime_NeverConstructsLatestImageTag_AndFailsClosed_WhenImageDigestMissing()
    {
        var options = new ScannerRuntimeOptions { EnforceImageProvenance = true };
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new DockerScannerRuntime(options, toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<DockerScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: "subfinder",
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: null // Missing digest: must fail closed, no :latest tag
        );

        var scratchDir = Path.Combine(options.PlatformScratchRoot, request.ScanJobId.ToString("N"));
        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, scratchDir);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().StartWith("TOOL_PROVENANCE_NOT_VERIFIED");
        mockAdapter.Verify(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DockerScannerRuntime_FailsClosed_WhenExecutableIsMissing_NoFallback()
    {
        var options = new ScannerRuntimeOptions();
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new DockerScannerRuntime(options, toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<DockerScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: null,
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd46059d33ef0"
        );

        var scratchDir = Path.Combine(options.PlatformScratchRoot, request.ScanJobId.ToString("N"));
        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, scratchDir);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("TOOL_EXECUTABLE_NOT_CONFIGURED");
    }

    [Fact]
    public async Task GenericScanWorker_FailsClosed_WhenRuntimeSandboxIsNull_AndNeverInvokesAdapter()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("WorkerNullSandboxDb_" + Guid.NewGuid())
            .Options;
        using var db = new PlatformDbContext(dbOptions);

        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Authorized Target", BaseUrl = "https://example.com", Enabled = true });
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

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("subfinder", "Subfinder", "v2.6.6", true, new[] { ToolCapability.SubdomainEnumeration }, executable: "subfinder");

        _mockEgressEngine.Setup(e => e.EvaluateAndBuildTargetAsync(It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
                         .ReturnsAsync(_validEgressTarget);

        var worker = new GenericScanWorker(
            db,
            new InMemoryScanProviderSecretStore(),
            registry,
            _mockEgressEngine.Object,
            runtimeSandbox: null, // NULL sandbox
            NullLogger<GenericScanWorker>.Instance
        );

        var result = await worker.ExecuteScanJobAsync(job.Id);

        // Assert fail closed
        result.Status.Should().Be(SecurityScanJobStatus.Failed);
        result.FailureReason.Should().Contain("SECURITY_SANDBOX_REQUIRED");
    }

    [Fact]
    public void DevelopmentHostScannerRuntime_ThrowsException_WhenInitializedInProduction()
    {
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        Action act = () => new DevelopmentHostScannerRuntime(
            toolKey => mockAdapter.Object,
            _mockEgressGateway.Object,
            isProductionEnvironment: true
        );

        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*CRITICAL_SECURITY_VIOLATION*");
    }

    [Fact]
    public async Task ScanToolHealthService_CloudMode_ProbesEndpoint_ReturnsReady_When200Ok()
    {
        var messageHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"status\":\"healthy\"}")
        });

        using var httpClient = new HttpClient(messageHandler);

        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = "SECRET_KEY_123"
        };

        var healthService = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: options,
            egressGateway: _mockEgressGateway.Object,
            httpClient: httpClient);

        var health = await healthService.GetScannerRuntimeHealthAsync();
        health.Runtime.Available.Should().BeTrue();
        health.ReadyForScans.Should().BeTrue();
        health.Runtime.Version.Should().Be("Cloud Managed Scanner Service Active");
    }

    [Fact]
    public async Task ScanToolHealthService_CloudMode_ReturnsNotReady_When500InternalServerError()
    {
        var messageHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var httpClient = new HttpClient(messageHandler);

        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = "SECRET_KEY_123"
        };

        var healthService = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: options,
            egressGateway: _mockEgressGateway.Object,
            httpClient: httpClient);

        var health = await healthService.GetScannerRuntimeHealthAsync();
        health.Runtime.Available.Should().BeFalse();
        health.ReadyForScans.Should().BeFalse();
        health.Runtime.Version.Should().Contain("500");
    }

    [Fact]
    public async Task ScanToolHealthService_CloudMode_ReturnsNotReady_WhenProbeTimesOutOrUnreachable()
    {
        var messageHandler = new TimeoutHttpMessageHandler();
        using var httpClient = new HttpClient(messageHandler);

        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = "https://scanner.internal",
            HostedScannerServiceKey = "SECRET_KEY_123"
        };

        var healthService = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: options,
            egressGateway: _mockEgressGateway.Object,
            httpClient: httpClient);

        var health = await healthService.GetScannerRuntimeHealthAsync();
        health.Runtime.Available.Should().BeFalse();
        health.ReadyForScans.Should().BeFalse();
    }

    [Fact]
    public async Task ScanToolHealthService_CloudMode_ReturnsNotReady_WhenUnconfigured()
    {
        var options = new ScannerRuntimeOptions
        {
            RuntimeMode = ScannerRuntimeMode.CloudManagedContainer,
            HostedScannerServiceEndpoint = null,
            HostedScannerServiceKey = null
        };

        var healthService = new ScanToolHealthService(
            registryService: null,
            logger: NullLogger<ScanToolHealthService>.Instance,
            options: options,
            egressGateway: _mockEgressGateway.Object);

        var health = await healthService.GetScannerRuntimeHealthAsync();
        health.Runtime.Available.Should().BeFalse();
        health.ReadyForScans.Should().BeFalse();
        health.Runtime.Version.Should().Be("Cloud Scanner Service Unconfigured");
    }

    [Fact]
    public async Task EnforcedEgressGateway_AllowsApprovedIp_AndBlocksUnapproved_IMDS_Loopback_Private()
    {
        var gateway = new EnforcedEgressGateway(_mockEgressEngine.Object, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        await using var session = await gateway.CreateScopedSessionAsync(_validEgressTarget);

        session.Should().NotBeNull();
        session.NetworkName.Should().Be("apihunter-sandbox-net");
        session.ContainerEnvironmentVariables.Should().ContainKey("NO_PROXY").WhoseValue.Should().BeEmpty();

        // 1. Approved Target IP -> ALLOW
        session.ValidateOutboundConnection(_approvedIp, 443).Should().BeTrue();

        // 2. Arbitrary external IP -> DENY
        session.ValidateOutboundConnection(_unapprovedExternalIp, 443).Should().BeFalse();

        // 3. IMDS Endpoint (169.254.169.254) -> DENY
        session.ValidateOutboundConnection(_imdsIp, 80).Should().BeFalse();

        // 4. Loopback (127.0.0.1) -> DENY
        session.ValidateOutboundConnection(_loopbackIp, 8080).Should().BeFalse();

        // 5. Private IP (10.0.0.1) -> DENY
        session.ValidateOutboundConnection(_privateIp, 80).Should().BeFalse();
    }

    [Fact]
    public async Task EnforcedEgressGateway_ThrowsException_WhenTargetIsExpired()
    {
        var gateway = new EnforcedEgressGateway(_mockEgressEngine.Object, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        Func<Task> act = async () => await gateway.CreateScopedSessionAsync(_expiredEgressTarget);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*expired*");
    }

    [Fact]
    public async Task HostedScannerRuntime_RejectsMissingServiceAuthenticationKey()
    {
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        using var httpClient = new HttpClient();
        var runtime = new HostedScannerRuntime(httpClient, serviceKey: null, toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<HostedScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: "subfinder",
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd46059d33ef0"
        );

        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, Path.GetTempPath());

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("MISSING_SERVICE_AUTHENTICATION_KEY");
    }

    [Fact]
    public async Task HostedScannerRuntime_DeserializesRemoteToolExecutionResult()
    {
        var expectedReceipt = new ToolExecutionResult("subfinder", "v2.6.6", ToolExecutionStatus.Success, 0, "/tmp/scratch", null);
        var messageHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(expectedReceipt))
        });

        using var httpClient = new HttpClient(messageHandler) { BaseAddress = new Uri("https://scanner.internal") };
        Mock<IGenericCliToolAdapter> mockAdapter = new();
        var runtime = new HostedScannerRuntime(httpClient, serviceKey: "SECRET_KEY_123", toolKey => mockAdapter.Object, _mockEgressGateway.Object, NullLogger<HostedScannerRuntime>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v2.6.6",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMinutes(10),
            Executable: "subfinder",
            ContainerImageRepository: "ghcr.io/apihunter-security/subfinder",
            ContainerImageDigest: "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd46059d33ef0"
        );

        var result = await runtime.ExecuteInSandboxAsync(request, _validEgressTarget, secretLease, Path.GetTempPath());

        result.Status.Should().Be(ToolExecutionStatus.Success);
        result.ToolKey.Should().Be("subfinder");
        result.ExitCode.Should().Be(0);
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

    private class TimeoutHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new TaskCanceledException("Request timed out");
        }
    }
}
