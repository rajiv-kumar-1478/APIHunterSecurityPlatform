using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Orchestration;
using Platform.Application.Scanning.Orchestration.Contracts;
using Xunit;

namespace Platform.UnitTests.Scanning.Orchestration;

public class DeploymentConcurrencyGateTests
{
    private readonly MockDeploymentLeaseStore _store;
    private readonly DeploymentConcurrencyGate _gate;

    public DeploymentConcurrencyGateTests()
    {
        _store = new MockDeploymentLeaseStore();
        _gate = new DeploymentConcurrencyGate(_store, NullLogger<DeploymentConcurrencyGate>.Instance);
    }

    [Fact]
    public async Task TryAcquireLease_InitialRequest_Succeeds()
    {
        var tenantId = Guid.NewGuid();
        var appId = "app-web-prod";
        var jobId = Guid.NewGuid();

        var (acquired, lease) = await _gate.TryAcquireLeaseAsync(tenantId, appId, jobId, TimeSpan.FromMinutes(10));

        Assert.True(acquired);
        Assert.NotNull(lease);
        Assert.Equal(jobId, lease.ScanJobId);
    }

    [Fact]
    public async Task TryAcquireLease_ConcurrentActiveRequest_Blocked()
    {
        var tenantId = Guid.NewGuid();
        var appId = "app-web-prod";
        var job1 = Guid.NewGuid();
        var job2 = Guid.NewGuid();

        var (acquired1, lease1) = await _gate.TryAcquireLeaseAsync(tenantId, appId, job1, TimeSpan.FromMinutes(10));
        var (acquired2, lease2) = await _gate.TryAcquireLeaseAsync(tenantId, appId, job2, TimeSpan.FromMinutes(10));

        Assert.True(acquired1);
        Assert.False(acquired2);
        Assert.Null(lease2);
    }

    [Fact]
    public async Task TryAcquireLease_ExpiredLeaseFromCrashedWorker_ReclaimsSuccessfully()
    {
        var tenantId = Guid.NewGuid();
        var appId = "app-web-prod";
        var crashedJobId = Guid.NewGuid();
        var newJobId = Guid.NewGuid();

        // Expired lease in store (5 minutes ago)
        var expiredLease = new DeploymentScanLease(
            LeaseId: Guid.NewGuid(),
            TenantId: tenantId,
            ApplicationId: appId,
            ScanJobId: crashedJobId,
            AcquiredAtUtc: DateTime.UtcNow.AddMinutes(-15),
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(-5),
            LastHeartbeatAtUtc: DateTime.UtcNow.AddMinutes(-5)
        );
        await _store.TryInsertLeaseAsync(expiredLease);

        var (acquired, newLease) = await _gate.TryAcquireLeaseAsync(tenantId, appId, newJobId, TimeSpan.FromMinutes(10));

        Assert.True(acquired);
        Assert.NotNull(newLease);
        Assert.Equal(newJobId, newLease.ScanJobId);
    }

    [Fact]
    public async Task ReleaseLease_AllowsSubsequentJobAcquisition()
    {
        var tenantId = Guid.NewGuid();
        var appId = "app-web-prod";
        var job1 = Guid.NewGuid();
        var job2 = Guid.NewGuid();

        var (acquired1, lease1) = await _gate.TryAcquireLeaseAsync(tenantId, appId, job1, TimeSpan.FromMinutes(10));
        Assert.True(acquired1);

        var released = await _gate.ReleaseLeaseAsync(lease1!.LeaseId);
        Assert.True(released);

        var (acquired2, lease2) = await _gate.TryAcquireLeaseAsync(tenantId, appId, job2, TimeSpan.FromMinutes(10));
        Assert.True(acquired2);
        Assert.NotNull(lease2);
        Assert.Equal(job2, lease2.ScanJobId);
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
            if (!match.Equals(default(System.Collections.Generic.KeyValuePair<string, DeploymentScanLease>)))
            {
                _leases.TryRemove(match.Key, out _);
                return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }
    }
}
