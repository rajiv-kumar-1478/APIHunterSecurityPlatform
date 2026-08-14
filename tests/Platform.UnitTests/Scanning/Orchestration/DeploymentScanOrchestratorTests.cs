using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Orchestration;
using Platform.Application.Scanning.Orchestration.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Verification;
using Platform.Application.Scanning.Verification.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Orchestration;

public class DeploymentScanOrchestratorTests
{
    private readonly DeploymentScanOrchestrator _orchestrator;
    private readonly MockDeploymentLeaseStore _leaseStore;
    private readonly ScanToolRegistry _toolRegistry;

    public DeploymentScanOrchestratorTests()
    {
        _leaseStore = new MockDeploymentLeaseStore();
        var concurrencyGate = new DeploymentConcurrencyGate(_leaseStore, NullLogger<DeploymentConcurrencyGate>.Instance);

        var discoveryEngine = new JsDiscoveryEngine(new System.Net.Http.HttpClient(), NullLogger<JsDiscoveryEngine>.Instance);
        var astAnalyzer = new JsAstAnalyzer(NullLogger<JsAstAnalyzer>.Instance);
        var secretAnalyzer = new JsSecretAnalyzer(NullLogger<JsSecretAnalyzer>.Instance);
        var verificationPlanner = new VerificationPlanner(NullLogger<VerificationPlanner>.Instance);

        var bugHunterParser = new BugHunterOutputParser(NullLogger<BugHunterOutputParser>.Instance);
        var bugHunterAdapter = new BugHunterAdapter(bugHunterParser);

        _toolRegistry = new ScanToolRegistry(new IScanToolAdapter[] { bugHunterAdapter });

        _orchestrator = new DeploymentScanOrchestrator(
            concurrencyGate,
            discoveryEngine,
            astAnalyzer,
            secretAnalyzer,
            verificationPlanner,
            _toolRegistry,
            NullLogger<DeploymentScanOrchestrator>.Instance
        );
    }

    [Fact]
    public async Task ExecuteDeploymentScan_ColdStart_ExecutesFullDiscoveryAndBugHunter()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var appId = "app-portal";
        var deploymentId = "dep-101";
        var targetUrl = "https://app.example.com";

        var record = await _orchestrator.ExecuteDeploymentScanAsync(
            scanJobId: scanJobId,
            tenantId: tenantId,
            applicationId: appId,
            deploymentId: deploymentId,
            commitSha: "sha-1",
            environment: "Production",
            targetUrl: targetUrl,
            policy: new ApplicationScanPolicy(appId),
            baselineAssets: null, // Cold start
            baselineGraph: null
        );

        Assert.Equal(DeploymentScanStage.Completed, record.Stage);
        Assert.Equal(scanJobId, record.ScanJobId);
        Assert.True(record.JsChanged);
        Assert.True(record.ApiSurfaceChanged);
        Assert.Null(record.FailureReason);
    }

    [Fact]
    public async Task ExecuteDeploymentScan_ConcurrentScanActive_FailsClosedWithTelemetry()
    {
        var scanJobId1 = Guid.NewGuid();
        var scanJobId2 = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var appId = "app-portal";

        // Hold active lease manually
        var activeLease = new DeploymentScanLease(
            LeaseId: Guid.NewGuid(),
            TenantId: tenantId,
            ApplicationId: appId,
            ScanJobId: scanJobId1,
            AcquiredAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            LastHeartbeatAtUtc: DateTime.UtcNow
        );
        await _leaseStore.TryInsertLeaseAsync(activeLease);

        var record = await _orchestrator.ExecuteDeploymentScanAsync(
            scanJobId: scanJobId2,
            tenantId: tenantId,
            applicationId: appId,
            deploymentId: "dep-102",
            commitSha: "sha-2",
            environment: "Production",
            targetUrl: "https://app.example.com"
        );

        Assert.Equal(DeploymentScanStage.Failed, record.Stage);
        Assert.Equal("CONCURRENT_SCAN_ACTIVE", record.FailureReason);
    }

    [Fact]
    public async Task ExecuteDeploymentScan_DisallowedEnvironment_SkippedByPolicy()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var appId = "app-portal";

        var policy = new ApplicationScanPolicy(
            ApplicationId: appId,
            AllowedEnvironments: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Production" }
        );

        var record = await _orchestrator.ExecuteDeploymentScanAsync(
            scanJobId: scanJobId,
            tenantId: tenantId,
            applicationId: appId,
            deploymentId: "dep-preview-1",
            commitSha: "sha-preview",
            environment: "Development", // Not in allowlist
            targetUrl: "https://dev.example.com",
            policy: policy
        );

        Assert.Equal(DeploymentScanStage.SkippedByPolicy, record.Stage);
        Assert.False(record.ActiveVerificationPerformed);
    }

    private sealed class MockDeploymentLeaseStore : IDeploymentLeaseStore
    {
        private readonly ConcurrentDictionary<string, DeploymentScanLease> _leases = new();

        public Task<DeploymentScanLease?> GetActiveLeaseAsync(Guid tenantId, string applicationId, CancellationToken ct = default)
        {
            var key = $"{tenantId}:{applicationId}";
            _leases.TryGetValue(key, out var lease);
            return Task.FromResult(lease);
        }

        public Task<bool> TryInsertLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default)
        {
            var key = $"{lease.TenantId}:{lease.ApplicationId}";
            return Task.FromResult(_leases.TryAdd(key, lease));
        }

        public Task<bool> TryUpdateLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default)
        {
            var key = $"{lease.TenantId}:{lease.ApplicationId}";
            _leases[key] = lease;
            return Task.FromResult(true);
        }

        public Task<bool> DeleteLeaseAsync(Guid leaseId, CancellationToken ct = default)
        {
            var match = _leases.FirstOrDefault(kv => kv.Value.LeaseId == leaseId);
            if (!match.Equals(default(KeyValuePair<string, DeploymentScanLease>)))
            {
                _leases.TryRemove(match.Key, out _);
                return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }
    }
}
