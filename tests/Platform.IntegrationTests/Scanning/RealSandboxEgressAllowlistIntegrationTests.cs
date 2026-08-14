using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Execution;
using Platform.Application.Scanning.Execution.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.IntegrationTests.Scanning;

/// <summary>
/// SPEC-008.11.3.3 Real Scanner Process Egress Boundary Integration Tests.
/// Validates that an actual OS child process spawned by the sandbox runtime executes
/// through the Enforced Egress Gateway, connects to approved provider destinations,
/// and is physically blocked when attempting to reach undeclared or prohibited destinations.
/// </summary>
public class RealSandboxEgressAllowlistIntegrationTests
{
    private readonly EgressPolicyEngine _policyEngine;
    private readonly IPAddress _githubApprovedIp;
    private readonly IPAddress _targetApprovedIp;
    private readonly IPAddress _undeclaredExternalIp;
    private readonly IPAddress _imdsProhibitedIp;
    private readonly IPAddress _privateProhibitedIp;

    public RealSandboxEgressAllowlistIntegrationTests()
    {
        _policyEngine = new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance);
        _githubApprovedIp = IPAddress.Parse("140.82.121.3");
        _targetApprovedIp = IPAddress.Parse("93.184.216.34");
        _undeclaredExternalIp = IPAddress.Parse("198.51.100.99");
        _imdsProhibitedIp = IPAddress.Parse("169.254.169.254");
        _privateProhibitedIp = IPAddress.Parse("10.0.0.1");
    }

    [Fact]
    public async Task RealProcess_ApprovedDestination_IsReachable()
    {
        var scanJobId = Guid.NewGuid();
        var customEgressPolicy = new EgressPolicyEngine(
            NullLogger<EgressPolicyEngine>.Instance,
            host => Task.FromResult(host.Contains("github") ? new[] { _githubApprovedIp } : new[] { _targetApprovedIp })
        );

        var realGateway = new EnforcedEgressGateway(customEgressPolicy, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        var target = new EgressTarget(
            RawTargetUrl: "https://api.github.com",
            CanonicalHost: "api.github.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { _githubApprovedIp, _targetApprovedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        await using var session = await realGateway.CreateScopedSessionAsync(target);
        await using var proxyServer = new EnforcedEgressProxyServer(session, host => Task.FromResult(new[] { _githubApprovedIp }), NullLogger.Instance);
        proxyServer.Start();

        // Real CLI adapter executing real curl.exe process on the host
        var realCliAdapter = new GenericCliToolAdapter("curl", NullLogger<GenericCliToolAdapter>.Instance);
        var authorizedManifest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["curl"] = "curl.exe"
        };

        var secretLease = new ProviderSecretLease(
            providerKey: "curl",
            secrets: new Dictionary<string, string>
            {
                ["HTTP_PROXY"] = proxyServer.ProxyEndpoint,
                ["HTTPS_PROXY"] = proxyServer.ProxyEndpoint,
                ["ALL_PROXY"] = proxyServer.ProxyEndpoint,
                ["NO_PROXY"] = ""
            },
            duration: TimeSpan.FromMinutes(10)
        );

        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", "apihunter_test_probe_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);

        try
        {
            var req = new ToolExecutionRequest(
                ToolKey: "curl",
                Version: "1.0.0",
                Arguments: new Dictionary<string, string>
                {
                    ["-s"] = "",
                    ["-o"] = "NUL",
                    ["-w"] = "%{http_code}",
                    ["--url"] = "http://api.github.com/rate_limit"
                },
                ScanJobId: scanJobId,
                Timeout: TimeSpan.FromSeconds(15),
                Executable: "curl.exe",
                ContainerImageRepository: "curl",
                ContainerImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                AuthorizedManifest: authorizedManifest
            );

            // Execute real child process!
            var result = await realCliAdapter.ExecuteAsync(req, secretLease, scratch);

            result.Status.Should().Be(ToolExecutionStatus.Success);
            result.ExitCode.Should().Be(0);
        }
        finally
        {
            if (Directory.Exists(scratch)) Directory.Delete(scratch, true);
        }
    }

    [Fact]
    public async Task RealProcess_UndeclaredDestination_IsBlocked()
    {
        var scanJobId = Guid.NewGuid();
        var customEgressPolicy = new EgressPolicyEngine(
            NullLogger<EgressPolicyEngine>.Instance,
            host => Task.FromResult(host.Contains("github") ? new[] { _githubApprovedIp } : new[] { _targetApprovedIp })
        );

        var realGateway = new EnforcedEgressGateway(customEgressPolicy, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        var target = new EgressTarget(
            RawTargetUrl: "https://api.github.com",
            CanonicalHost: "api.github.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { _githubApprovedIp, _targetApprovedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        await using var session = await realGateway.CreateScopedSessionAsync(target);
        // DNS resolver maps unauthorized host to unapproved external IP (198.51.100.99)
        await using var proxyServer = new EnforcedEgressProxyServer(session, host => Task.FromResult(new[] { _undeclaredExternalIp }), NullLogger.Instance);
        proxyServer.Start();

        var realCliAdapter = new GenericCliToolAdapter("curl", NullLogger<GenericCliToolAdapter>.Instance);
        var authorizedManifest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["curl"] = "curl.exe"
        };

        var secretLease = new ProviderSecretLease(
            providerKey: "curl",
            secrets: new Dictionary<string, string>
            {
                ["HTTP_PROXY"] = proxyServer.ProxyEndpoint,
                ["HTTPS_PROXY"] = proxyServer.ProxyEndpoint,
                ["ALL_PROXY"] = proxyServer.ProxyEndpoint,
                ["NO_PROXY"] = ""
            },
            duration: TimeSpan.FromMinutes(10)
        );

        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", "apihunter_test_probe_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);

        try
        {
            var req = new ToolExecutionRequest(
                ToolKey: "curl",
                Version: "1.0.0",
                Arguments: new Dictionary<string, string>
                {
                    ["-s"] = "",
                    ["-o"] = "NUL",
                    ["-f"] = "", // --fail causes curl to exit non-zero on HTTP 403 Forbidden
                    ["--url"] = "http://unauthorized-provider.internal/probe"
                },
                ScanJobId: scanJobId,
                Timeout: TimeSpan.FromSeconds(15),
                Executable: "curl.exe",
                ContainerImageRepository: "curl",
                ContainerImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                AuthorizedManifest: authorizedManifest
            );

            // Execute real child process!
            var result = await realCliAdapter.ExecuteAsync(req, secretLease, scratch);

            // Curl must fail with exit code (e.g. 22: HTTP 403 Forbidden from proxy)
            result.Status.Should().Be(ToolExecutionStatus.Failed);
            result.ExitCode.Should().NotBe(0);
        }
        finally
        {
            if (Directory.Exists(scratch)) Directory.Delete(scratch, true);
        }
    }

    [Fact]
    public async Task RealProcess_ProhibitedDestination_NeverStarts()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var dbContext = new PlatformDbContext(dbOptions);

        var truffleHogParser = new TruffleHogOutputParser(NullLogger<TruffleHogOutputParser>.Instance);
        var truffleHogAdapter = new TruffleHogAdapter(truffleHogParser);
        var toolRegistry = new ScanToolRegistry(new[] { truffleHogAdapter });

        var realGateway = new EnforcedEgressGateway(_policyEngine, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);

        bool cliAdapterEverCalled = false;
        var realCliAdapter = new Mock<IGenericCliToolAdapter>();
        realCliAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback(() => cliAdapterEverCalled = true)
            .ReturnsAsync(new ToolExecutionResult("trufflehog", "3.96.0", ToolExecutionStatus.Success, 0, "{}", null));

        var realSandbox = new DevelopmentHostScannerRuntime(
            cliAdapterFactory: key => realCliAdapter.Object,
            egressGateway: realGateway,
            logger: NullLogger<DevelopmentHostScannerRuntime>.Instance
        );

        var provVerifier = new Mock<IToolProvenanceVerifier>();
        provVerifier.Setup(v => v.VerifyManifestDigestAsync(It.IsAny<ScanToolManifest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanToolManifest m, CancellationToken ct) => new ProvenanceVerificationResult(true, m.ContainerImageDigest, m.ContainerImageDigest, null));

        var engine = new ScanExecutionEngine(
            toolRegistry,
            dbContext,
            NullLogger<ScanExecutionEngine>.Instance,
            realSandbox,
            ingestionEngine: null,
            _policyEngine,
            provVerifier.Object
        );

        var invocations = new List<PlannedToolInvocation>
        {
            new("trufflehog", "3.96.0", ScannerExecutionPhase.StaticAnalysis, new[] { "secret.scan" }, Array.Empty<string>(), "Secret scan")
        };

        // Prohibited IMDS endpoint in verification destinations
        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.SourceRepository,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: invocations.AsReadOnly(),
            ExecutionSequence: new[] { "trufflehog" },
            RuleSetVersions: new Dictionary<string, string> { ["trufflehog"] = "3.96.0" },
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "plan_real_sandbox_prohibited",
            PlannedAtUtc: DateTime.UtcNow,
            TargetUrl: "https://api.github.com",
            AdditionalOptions: new Dictionary<string, string>
            {
                ["enable_live_verification"] = "true",
                ["verification_destinations"] = "http://169.254.169.254/latest/meta-data"
            }
        );

        var result = await engine.ExecutePlanAsync(plan);

        result.OverallStatus.Should().Be(OverallScanExecutionStatus.Failed);
        result.Invocations.Should().ContainSingle(i => i.Status == ToolInvocationStatus.Failed && i.ErrorMessage.Contains("PROVIDER_EGRESS_UNAUTHORIZED"));
        cliAdapterEverCalled.Should().BeFalse("Real sandbox/CLI adapter MUST NEVER be called when verification destination is prohibited.");
    }

    [Fact]
    public async Task RealProcess_CannotBypassProxyWithDirectConnection()
    {
        var scanJobId = Guid.NewGuid();
        var customEgressPolicy = new EgressPolicyEngine(
            NullLogger<EgressPolicyEngine>.Instance,
            host => Task.FromResult(new[] { _githubApprovedIp })
        );

        var realGateway = new EnforcedEgressGateway(customEgressPolicy, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        var target = new EgressTarget(
            RawTargetUrl: "https://api.github.com",
            CanonicalHost: "api.github.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { _githubApprovedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        await using var session = await realGateway.CreateScopedSessionAsync(target);

        // Verify session strictly enforces empty NO_PROXY
        session.ContainerEnvironmentVariables["NO_PROXY"].Should().BeEmpty("NO_PROXY must be empty to prevent proxy bypass");

        // Start a real live local test listener
        using var localListener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        localListener.Start();
        var localPort = ((IPEndPoint)localListener.LocalEndpoint).Port;

        // Start proxy server backed by the real gateway session
        await using var proxyServer = new EnforcedEgressProxyServer(session, host => Task.FromResult(new[] { IPAddress.Loopback }), NullLogger.Instance);
        proxyServer.Start();

        var realCliAdapter = new GenericCliToolAdapter("curl", NullLogger<GenericCliToolAdapter>.Instance);
        var authorizedManifest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["curl"] = "curl.exe"
        };

        var secretLease = new ProviderSecretLease(
            providerKey: "curl",
            secrets: new Dictionary<string, string>
            {
                ["HTTP_PROXY"] = proxyServer.ProxyEndpoint,
                ["HTTPS_PROXY"] = proxyServer.ProxyEndpoint,
                ["ALL_PROXY"] = proxyServer.ProxyEndpoint,
                ["NO_PROXY"] = ""
            },
            duration: TimeSpan.FromMinutes(10)
        );

        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", "apihunter_test_probe_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);

        try
        {
            // Attempt request to the active local loopback listener
            var req = new ToolExecutionRequest(
                ToolKey: "curl",
                Version: "1.0.0",
                Arguments: new Dictionary<string, string>
                {
                    ["-s"] = "",
                    ["-o"] = "NUL",
                    ["-f"] = "", // --fail causes curl to exit non-zero on HTTP 403 Forbidden
                    ["--url"] = $"http://127.0.0.1:{localPort}/bypass-test"
                },
                ScanJobId: scanJobId,
                Timeout: TimeSpan.FromSeconds(10),
                Executable: "curl.exe",
                ContainerImageRepository: "curl",
                ContainerImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                AuthorizedManifest: authorizedManifest
            );

            var result = await realCliAdapter.ExecuteAsync(req, secretLease, scratch);

            // Proxy must intercept and block connection to 127.0.0.1 (prohibited loopback), returning 403 and causing curl to fail
            result.Status.Should().Be(ToolExecutionStatus.Failed);
            result.ExitCode.Should().NotBe(0);
        }
        finally
        {
            localListener.Stop();
            if (Directory.Exists(scratch)) Directory.Delete(scratch, true);
        }
    }
}
