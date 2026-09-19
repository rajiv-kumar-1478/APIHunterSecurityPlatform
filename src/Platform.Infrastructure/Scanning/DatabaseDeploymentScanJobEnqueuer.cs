using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Verification;
using Platform.Application.Scanning.Verification.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Production implementation of <see cref="IDeploymentScanJobEnqueuer"/>.
///
/// Creates a durable <see cref="SecurityScanJob"/> owned by the tenant from the
/// resolved target. The job is tagged <c>TriggeredBy = "CiCdWebhook"</c> and has
/// a null <c>RequestedByUserId</c> (system-initiated — matches campaign scheduler contract).
///
/// Throws rather than returning <see cref="Guid.Empty"/> on failure; the handler
/// must not record idempotency until a durable identifier is confirmed.
/// </summary>
public sealed class DatabaseDeploymentScanJobEnqueuer : IDeploymentScanJobEnqueuer
{
    private const string TriggerSource = "CiCdWebhook";
    // Default scan profile for CI/CD triggered jobs.
    // Standard gives a broader coverage than Recon for deployment verification.
    private const SecurityScanProfileType DefaultProfile = SecurityScanProfileType.Standard;

    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<DatabaseDeploymentScanJobEnqueuer> _logger;

    public DatabaseDeploymentScanJobEnqueuer(
        IPlatformDbContext dbContext,
        ILogger<DatabaseDeploymentScanJobEnqueuer> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<Guid> EnqueueDeploymentScanAsync(
        DeploymentTargetResolution resolution,
        DeploymentWebhookRequest request,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(request);

        if (resolution.TenantId == Guid.Empty)
        {
            throw new InvalidOperationException(
                $"Resolved tenant for application '{resolution.ApplicationId}' is Guid.Empty. Deployment scan rejected.");
        }

        if (string.IsNullOrWhiteSpace(resolution.AuthorizedTargetUrl))
        {
            throw new InvalidOperationException(
                $"Resolved target URL for application '{resolution.ApplicationId}' is empty. Deployment scan rejected.");
        }

        var jobId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var scanJob = new SecurityScanJob
        {
            Id = jobId,
            RepositoryId = null,            // Deployment webhook jobs are target-based, not repo-based.
            TargetId = null,                // No SecurityTarget FK — URL is authoritative from RegisteredApplication.
            TargetUrl = resolution.AuthorizedTargetUrl.Trim(),
            ScanProfile = DefaultProfile,
            Status = SecurityScanJobStatus.Queued,
            TenantId = resolution.TenantId,
            RequestedByUserId = null,       // System-initiated — same pattern as CampaignScheduler.
            TriggeredBy = TriggerSource,
            ProviderKey = string.Empty,     // Provider resolved at execution time by GenericScanWorker.
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = now,
            JobVersion = 1
        };

        _dbContext.SecurityScanJobs.Add(scanJob);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Enqueued deployment scan job '{JobId}' for application '{ApplicationId}' " +
            "at '{TargetUrl}' (Deployment: '{DeploymentId}', Commit: '{CommitSha}', Tenant: '{TenantId}').",
            jobId,
            resolution.ApplicationId,
            resolution.AuthorizedTargetUrl,
            request.DeploymentId,
            request.CommitSha ?? "N/A",
            resolution.TenantId);

        return jobId;
    }
}
