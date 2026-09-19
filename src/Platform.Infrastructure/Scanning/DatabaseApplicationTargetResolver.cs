using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Verification;
using Platform.Application.Scanning.Verification.Contracts;
using Platform.Domain.Entities;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Production implementation of <see cref="IApplicationTargetResolver"/> that resolves
/// registered applications from the database and manages idempotency records.
///
/// Webhook secrets are stored Data-Protection-encrypted in <c>registered_applications</c>
/// and decrypted transiently in memory for HMAC verification. Processed webhook IDs are
/// recorded durably in <c>deployment_webhook_records</c> only after scan-job creation succeeds.
/// </summary>
public sealed class DatabaseApplicationTargetResolver : IApplicationTargetResolver
{
    private const string DataProtectionPurpose = "Platform.DeploymentWebhook.HmacSecret";

    private readonly IPlatformDbContext _dbContext;
    private readonly IDataProtector _protector;
    private readonly ILogger<DatabaseApplicationTargetResolver> _logger;

    public DatabaseApplicationTargetResolver(
        IPlatformDbContext dbContext,
        IDataProtectionProvider dataProtectionProvider,
        ILogger<DatabaseApplicationTargetResolver> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _protector = (dataProtectionProvider ?? throw new ArgumentNullException(nameof(dataProtectionProvider)))
            .CreateProtector(DataProtectionPurpose);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<DeploymentTargetResolution?> ResolveTargetAsync(string applicationId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return null;
        }

        var app = await _dbContext.RegisteredApplications
            .AsNoTracking()
            .FirstOrDefaultAsync(
                a => a.ApplicationId == applicationId && a.Enabled,
                ct);

        if (app == null)
        {
            _logger.LogWarning("Deployment webhook: application '{ApplicationId}' not found or disabled.", applicationId);
            return null;
        }

        return new DeploymentTargetResolution(
            TenantId: app.TenantId,
            ApplicationId: app.ApplicationId,
            AuthorizedTargetUrl: app.AuthorizedTargetUrl,
            Environment: app.Environment,
            IsAuthorized: true);
    }

    /// <inheritdoc />
    public async Task<string?> GetWebhookSecretAsync(string applicationId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return null;
        }

        var app = await _dbContext.RegisteredApplications
            .AsNoTracking()
            .FirstOrDefaultAsync(
                a => a.ApplicationId == applicationId && a.Enabled,
                ct);

        if (app == null || string.IsNullOrWhiteSpace(app.EncryptedWebhookSecret))
        {
            return null;
        }

        try
        {
            // Decrypt transiently in memory; never assigned to a field or logged.
            return _protector.Unprotect(app.EncryptedWebhookSecret);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt webhook secret for application '{ApplicationId}'.", applicationId);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<bool> HasWebhookBeenProcessedAsync(string webhookId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(webhookId))
        {
            return false;
        }

        return await _dbContext.DeploymentWebhookRecords
            .AsNoTracking()
            .AnyAsync(r => r.WebhookId == webhookId, ct);
    }

    /// <inheritdoc />
    public async Task MarkWebhookProcessedAsync(string webhookId, string applicationId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(webhookId) || string.IsNullOrWhiteSpace(applicationId))
        {
            return;
        }

        // Guard against concurrent duplicate insertions: check existence before inserting.
        // The PK unique constraint provides the final safety net at the DB layer.
        var alreadyExists = await _dbContext.DeploymentWebhookRecords
            .AsNoTracking()
            .AnyAsync(r => r.WebhookId == webhookId, ct);

        if (alreadyExists)
        {
            _logger.LogWarning(
                "MarkWebhookProcessedAsync called for webhook '{WebhookId}' that is already recorded. Skipping duplicate insert.",
                webhookId);
            return;
        }

        _dbContext.DeploymentWebhookRecords.Add(new DeploymentWebhookRecord
        {
            WebhookId = webhookId,
            ApplicationId = applicationId,
            ProcessedAtUtc = DateTime.UtcNow
        });

        await _dbContext.SaveChangesAsync(ct);
    }
}
