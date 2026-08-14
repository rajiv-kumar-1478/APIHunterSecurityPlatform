using System;
using System.Collections.Generic;
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
/// SPEC-008.11.3.1 Real Sandbox Egress Allowlist Enforcement Integration Tests.
/// Validates that the runtime container sandbox and Enforced Egress Gateway physically block
/// undeclared/unapproved destinations and only permit plan-authorized provider destinations.
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
    public async Task ExecuteRealSandbox_ApprovedProvider_IsReachable()
    {
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

        var gateway = new EnforcedEgressGateway(_policyEngine, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        await using var session = await gateway.CreateScopedSessionAsync(target);

        Task<IPAddress[]> DnsResolver(string host) => Task.FromResult(new[] { _githubApprovedIp });

        await using var proxyServer = new EnforcedEgressProxyServer(session, DnsResolver, NullLogger.Instance);
        proxyServer.Start();

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy(proxyServer.ProxyEndpoint),
            UseProxy = true
        };

        using var client = new HttpClient(handler);
        var response = await client.GetAsync("http://api.github.com/rate_limit");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues("X-Egress-Policy").Should().Contain("Approved");
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Be("GATEWAY_EGRESS_APPROVED");
    }

    [Fact]
    public async Task ExecuteRealSandbox_UndeclaredDestination_IsBlocked()
    {
        // Sandbox is authorized ONLY for api.github.com
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

        var gateway = new EnforcedEgressGateway(_policyEngine, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);
        await using var session = await gateway.CreateScopedSessionAsync(target);

        // DNS resolver maps undeclared host to unapproved external IP (198.51.100.99)
        Task<IPAddress[]> DnsResolver(string host) => Task.FromResult(new[] { _undeclaredExternalIp });

        await using var proxyServer = new EnforcedEgressProxyServer(session, DnsResolver, NullLogger.Instance);
        proxyServer.Start();

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy(proxyServer.ProxyEndpoint),
            UseProxy = true
        };

        using var client = new HttpClient(handler);
        var response = await client.GetAsync("http://unauthorized-provider.internal/probe");

        // The real sandbox gateway listener must physically block connection to undeclared IP
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        response.Headers.GetValues("X-Egress-Policy").Should().Contain("Blocked");
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("EGRESS_BLOCKED: Prohibited or unapproved destination IP");
    }

    [Fact]
    public async Task ExecuteRealSandbox_ProhibitedProvider_NeverStartsTool()
    {
        // Target containing prohibited IMDS / private IP
        var prohibitedTarget = new EgressTarget(
            RawTargetUrl: "http://169.254.169.254/latest/meta-data",
            CanonicalHost: "169.254.169.254",
            Port: 80,
            Scheme: "http",
            ApprovedIpAddresses: new HashSet<IPAddress> { _imdsProhibitedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        var gateway = new EnforcedEgressGateway(_policyEngine, new ScannerRuntimeOptions(), NullLogger<EnforcedEgressGateway>.Instance);

        // Attempting to create sandbox gateway session for prohibited address must throw immediately
        Func<Task> act = async () => await gateway.CreateScopedSessionAsync(prohibitedTarget);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*prohibited network address range*");
    }

    [Fact]
    public async Task ExecuteRealSandbox_AllowlistContainsOnlyPlanAuthorizedIPs()
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

        EgressTarget? capturedGatewayTarget = null;
        var mockGateway = new Mock<IEnforcedEgressGateway>();
        mockGateway.Setup(g => g.CreateScopedSessionAsync(It.IsAny<EgressTarget>(), It.IsAny<CancellationToken>()))
            .Callback<EgressTarget, CancellationToken>((target, ct) =>
            {
                capturedGatewayTarget = target;
            })
            .ReturnsAsync(Mock.Of<IEnforcedEgressGatewaySession>());

        var mockCliAdapter = new Mock<IGenericCliToolAdapter>();
        mockCliAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ToolExecutionResult(
                ToolKey: "trufflehog",
                Version: "3.96.0",
                Status: ToolExecutionStatus.Success,
                ExitCode: 0,
                ArtifactReference: "{}",
                ErrorCode: null
            ));

        var realSandbox = new DevelopmentHostScannerRuntime(
            cliAdapterFactory: key => mockCliAdapter.Object,
            egressGateway: mockGateway.Object,
            logger: NullLogger<DevelopmentHostScannerRuntime>.Instance
        );

        var customEgressPolicy = new EgressPolicyEngine(
            NullLogger<EgressPolicyEngine>.Instance,
            host => Task.FromResult(host.Contains("github") ? new[] { _githubApprovedIp } : new[] { _targetApprovedIp })
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
            customEgressPolicy,
            provVerifier.Object
        );

        var invocations = new List<PlannedToolInvocation>
        {
            new("trufflehog", "3.96.0", ScannerExecutionPhase.StaticAnalysis, new[] { "secret.scan" }, Array.Empty<string>(), "Secret scan")
        };

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
            PlanHash: "plan_real_sandbox_allowlist",
            PlannedAtUtc: DateTime.UtcNow,
            TargetUrl: "https://example.com",
            AdditionalOptions: new Dictionary<string, string>
            {
                ["enable_live_verification"] = "true",
                ["verification_destinations"] = "https://api.github.com"
            }
        );

        var result = await engine.ExecutePlanAsync(plan);

        result.OverallStatus.Should().Be(OverallScanExecutionStatus.Completed);
        capturedGatewayTarget.Should().NotBeNull();
        capturedGatewayTarget!.ApprovedIpAddresses.Should().Contain(_githubApprovedIp);
        capturedGatewayTarget.ApprovedIpAddresses.Should().Contain(_targetApprovedIp);
        capturedGatewayTarget.ApprovedIpAddresses.Should().NotContain(_undeclaredExternalIp);
        capturedGatewayTarget.ApprovedIpAddresses.Should().NotContain(_imdsProhibitedIp);
        capturedGatewayTarget.ApprovedIpAddresses.Should().NotContain(_privateProhibitedIp);
    }
}
