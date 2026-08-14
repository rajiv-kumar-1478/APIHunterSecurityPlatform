using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Orchestration.Contracts;

namespace Platform.Application.Scanning.Orchestration;

public interface IDeploymentLeaseStore
{
    Task<DeploymentScanLease?> GetActiveLeaseAsync(Guid tenantId, string applicationId, CancellationToken ct = default);
    Task<bool> TryInsertLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default);
    Task<bool> TryUpdateLeaseAsync(DeploymentScanLease lease, CancellationToken ct = default);
    Task<bool> DeleteLeaseAsync(Guid leaseId, CancellationToken ct = default);
}

/// <summary>
/// Authoritative durable concurrency gate preventing duplicate concurrent scans per (TenantId, ApplicationId).
/// Supports atomic claims, heartbeats, expiry detection, and worker crash recovery.
/// </summary>
public interface IDeploymentConcurrencyGate
{
    Task<(bool Acquired, DeploymentScanLease? Lease)> TryAcquireLeaseAsync(
        Guid tenantId,
        string applicationId,
        Guid scanJobId,
        TimeSpan leaseDuration,
        CancellationToken ct = default);

    Task<bool> HeartbeatAsync(Guid leaseId, TimeSpan extension, CancellationToken ct = default);

    Task<bool> ReleaseLeaseAsync(Guid leaseId, CancellationToken ct = default);
}
