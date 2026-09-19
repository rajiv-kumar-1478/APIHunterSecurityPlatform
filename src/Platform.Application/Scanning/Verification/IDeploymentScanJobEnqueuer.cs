using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Verification;

/// <summary>
/// Creates the durable <c>SecurityScanJob</c> for an authorized, signature-verified
/// deployment webhook.
///
/// This is a required collaborator of <see cref="DeploymentWebhookHandler"/>. The handler
/// must never report success without a durable job identifier, so there is deliberately no
/// default or no-op implementation: a deployment integration that cannot enqueue must fail
/// closed and allow the CI/CD caller to retry.
/// </summary>
public interface IDeploymentScanJobEnqueuer
{
    /// <summary>
    /// Persists a tenant-owned deployment scan job and returns its durable identifier.
    /// Implementations must be the authority for tenant ownership and must throw rather
    /// than return a fabricated identifier when persistence fails.
    /// </summary>
    Task<Guid> EnqueueDeploymentScanAsync(
        DeploymentTargetResolution resolution,
        DeploymentWebhookRequest request,
        CancellationToken ct = default);
}
