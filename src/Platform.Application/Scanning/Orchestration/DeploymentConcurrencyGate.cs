using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Orchestration.Contracts;

namespace Platform.Application.Scanning.Orchestration;

/// <summary>
/// Authoritative durable concurrency gate preventing duplicate concurrent scans per (TenantId, ApplicationId).
/// Supports atomic claims, heartbeats, expiry detection, and worker crash recovery.
/// </summary>
public sealed class DeploymentConcurrencyGate : IDeploymentConcurrencyGate
{
    private readonly IDeploymentLeaseStore _leaseStore;
    private readonly ILogger<DeploymentConcurrencyGate> _logger;

    public DeploymentConcurrencyGate(
        IDeploymentLeaseStore leaseStore,
        ILogger<DeploymentConcurrencyGate> logger)
    {
        _leaseStore = leaseStore ?? throw new ArgumentNullException(nameof(leaseStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<(bool Acquired, DeploymentScanLease? Lease)> TryAcquireLeaseAsync(
        Guid tenantId,
        string applicationId,
        Guid scanJobId,
        TimeSpan leaseDuration,
        CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var existingLease = await _leaseStore.GetActiveLeaseAsync(tenantId, applicationId, ct);

        if (existingLease != null)
        {
            // Check if lease is active and not expired
            if (existingLease.ExpiresAtUtc > now)
            {
                _logger.LogWarning("Deployment scan lease for app '{AppId}' (Tenant: {TenantId}) is already held by Job '{JobId}' until {Expires:O}.",
                    applicationId, tenantId, existingLease.ScanJobId, existingLease.ExpiresAtUtc);
                return (false, null);
            }

            // Lease expired (dead worker crash recovery) -> reclaim lease
            _logger.LogInformation("Reclaiming expired deployment scan lease for app '{AppId}' from previous job '{JobId}'.",
                applicationId, existingLease.ScanJobId);
            await _leaseStore.DeleteLeaseAsync(existingLease.LeaseId, ct);
        }

        var newLease = new DeploymentScanLease(
            LeaseId: Guid.NewGuid(),
            TenantId: tenantId,
            ApplicationId: applicationId,
            ScanJobId: scanJobId,
            AcquiredAtUtc: now,
            ExpiresAtUtc: now.Add(leaseDuration),
            LastHeartbeatAtUtc: now
        );

        var inserted = await _leaseStore.TryInsertLeaseAsync(newLease, ct);
        if (!inserted)
        {
            _logger.LogWarning("Race condition during lease acquisition for app '{AppId}'. Acquired by another worker.", applicationId);
            return (false, null);
        }

        _logger.LogInformation("Successfully acquired deployment scan lease '{LeaseId}' for app '{AppId}' (Job: {JobId}).",
            newLease.LeaseId, applicationId, scanJobId);

        return (true, newLease);
    }

    public async Task<bool> HeartbeatAsync(Guid leaseId, TimeSpan extension, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var lease = new DeploymentScanLease(leaseId, Guid.Empty, string.Empty, Guid.Empty, now, now.Add(extension), now);
        return await _leaseStore.TryUpdateLeaseAsync(lease, ct);
    }

    public async Task<bool> ReleaseLeaseAsync(Guid leaseId, CancellationToken ct = default)
    {
        _logger.LogInformation("Releasing deployment scan lease '{LeaseId}'.", leaseId);
        return await _leaseStore.DeleteLeaseAsync(leaseId, ct);
    }
}
