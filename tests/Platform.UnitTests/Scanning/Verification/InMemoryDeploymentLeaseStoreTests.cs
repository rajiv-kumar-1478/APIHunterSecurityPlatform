using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Orchestration;
using Platform.Application.Scanning.Orchestration.Contracts;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning.Verification;

/// <summary>
/// Unit tests for <see cref="InMemoryDeploymentLeaseStore"/>.
/// Verifies thread-safe insert / update / delete and tenant-scoped lookup semantics.
/// </summary>
public class InMemoryDeploymentLeaseStoreTests
{
    private readonly InMemoryDeploymentLeaseStore _store = new();

    private static DeploymentScanLease BuildLease(
        Guid? tenantId = null,
        string applicationId = "app-test",
        Guid? scanJobId = null,
        Guid? leaseId = null) => new()
    {
        LeaseId = leaseId ?? Guid.NewGuid(),
        TenantId = tenantId ?? Guid.NewGuid(),
        ApplicationId = applicationId,
        ScanJobId = scanJobId ?? Guid.NewGuid(),
        AcquiredAtUtc = DateTime.UtcNow,
        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5),
        WorkerInstanceId = "worker-001"
    };

    [Fact]
    public async Task GetActiveLease_WhenNoneExists_ReturnsNull()
    {
        var result = await _store.GetActiveLeaseAsync(Guid.NewGuid(), "app-x");
        Assert.Null(result);
    }

    [Fact]
    public async Task TryInsertLease_NewLease_ReturnsTrue()
    {
        var lease = BuildLease();
        var inserted = await _store.TryInsertLeaseAsync(lease);
        Assert.True(inserted);
    }

    [Fact]
    public async Task TryInsertLease_DuplicateLeaseId_ReturnsFalse()
    {
        var lease = BuildLease();
        await _store.TryInsertLeaseAsync(lease);

        var duplicated = await _store.TryInsertLeaseAsync(lease);
        Assert.False(duplicated);
    }

    [Fact]
    public async Task GetActiveLease_AfterInsert_ReturnsMatchingLease()
    {
        var tenantId = Guid.NewGuid();
        const string appId = "app-lookup";
        var lease = BuildLease(tenantId: tenantId, applicationId: appId);

        await _store.TryInsertLeaseAsync(lease);

        var found = await _store.GetActiveLeaseAsync(tenantId, appId);
        Assert.NotNull(found);
        Assert.Equal(lease.LeaseId, found!.LeaseId);
        Assert.Equal(appId, found.ApplicationId);
    }

    [Fact]
    public async Task GetActiveLease_DifferentTenant_ReturnsNull()
    {
        var lease = BuildLease(applicationId: "app-shared");
        await _store.TryInsertLeaseAsync(lease);

        // Different tenant with same app name must NOT see the other tenant's lease.
        var result = await _store.GetActiveLeaseAsync(Guid.NewGuid(), "app-shared");
        Assert.Null(result);
    }

    [Fact]
    public async Task TryUpdateLease_ExistingLease_UpdatesAndReturnsTrue()
    {
        var lease = BuildLease();
        await _store.TryInsertLeaseAsync(lease);

        var updatedLease = lease with { ExpiresAtUtc = DateTime.UtcNow.AddMinutes(15) };
        var updated = await _store.TryUpdateLeaseAsync(updatedLease);

        Assert.True(updated);

        var found = await _store.GetActiveLeaseAsync(lease.TenantId, lease.ApplicationId);
        Assert.NotNull(found);
        Assert.True(found!.ExpiresAtUtc > DateTime.UtcNow.AddMinutes(10));
    }

    [Fact]
    public async Task TryUpdateLease_NonExistentLease_ReturnsFalse()
    {
        var lease = BuildLease();
        var updated = await _store.TryUpdateLeaseAsync(lease);
        Assert.False(updated);
    }

    [Fact]
    public async Task DeleteLease_ExistingLease_RemovesAndReturnsTrue()
    {
        var lease = BuildLease();
        await _store.TryInsertLeaseAsync(lease);

        var deleted = await _store.DeleteLeaseAsync(lease.LeaseId);
        Assert.True(deleted);

        var found = await _store.GetActiveLeaseAsync(lease.TenantId, lease.ApplicationId);
        Assert.Null(found);
    }

    [Fact]
    public async Task DeleteLease_NonExistentLease_ReturnsFalse()
    {
        var deleted = await _store.DeleteLeaseAsync(Guid.NewGuid());
        Assert.False(deleted);
    }
}
