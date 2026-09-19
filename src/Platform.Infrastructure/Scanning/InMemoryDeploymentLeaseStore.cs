using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Orchestration;
using Platform.Application.Scanning.Orchestration.Contracts;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Thread-safe in-process deployment scan lease store backed by a ConcurrentDictionary.
/// Suitable for single-instance deployments and test harnesses.
/// For multi-process deployments replace with a PostgreSQL-backed implementation.
/// </summary>
public sealed class InMemoryDeploymentLeaseStore : IDeploymentLeaseStore
{
    // Keyed by LeaseId for fast delete/update; secondary lookup by (TenantId, ApplicationId).
    private readonly ConcurrentDictionary<Guid, DeploymentScanLease> _leases = new();

    public Task<DeploymentScanLease?> GetActiveLeaseAsync(Guid tenantId, string applicationId, CancellationToken ct = default)
    {
        DeploymentScanLease? found = null;
        foreach (var lease in _leases.Values)
        {
            if (lease.TenantId == tenantId &&
                string.Equals(lease.ApplicationId, applicationId, StringComparison.OrdinalIgnoreCase))
            {
                found = lease;
                break;
            }
        }

        return Task.FromResult(found);
    }

    public Task<bool> TryInsertLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default)
    {
        var inserted = _leases.TryAdd(lease.LeaseId, lease);
        return Task.FromResult(inserted);
    }

    public Task<bool> TryUpdateLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default)
    {
        if (!_leases.TryGetValue(lease.LeaseId, out _))
        {
            return Task.FromResult(false);
        }

        _leases[lease.LeaseId] = lease;
        return Task.FromResult(true);
    }

    public Task<bool> DeleteLeaseAsync(Guid leaseId, CancellationToken ct = default)
    {
        var removed = _leases.TryRemove(leaseId, out _);
        return Task.FromResult(removed);
    }
}
