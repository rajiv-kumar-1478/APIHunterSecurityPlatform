using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Verification;
using Platform.Domain.Entities;

namespace Platform.Infrastructure.Scanning;

public sealed class RegisteredApplicationService : IRegisteredApplicationService
{
    private const string DataProtectionPurpose = "Platform.DeploymentWebhook.HmacSecret";

    private readonly IPlatformDbContext _dbContext;
    private readonly IDataProtector _protector;
    private readonly ILogger<RegisteredApplicationService> _logger;

    public RegisteredApplicationService(
        IPlatformDbContext dbContext,
        IDataProtectionProvider dataProtectionProvider,
        ILogger<RegisteredApplicationService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _protector = (dataProtectionProvider ?? throw new ArgumentNullException(nameof(dataProtectionProvider)))
            .CreateProtector(DataProtectionPurpose);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IReadOnlyList<RegisteredApplicationDto>> GetApplicationsAsync(Guid tenantId, CancellationToken ct = default)
    {
        var apps = await _dbContext.RegisteredApplications
            .AsNoTracking()
            .Where(a => a.TenantId == tenantId)
            .OrderByDescending(a => a.CreatedAtUtc)
            .ToListAsync(ct);

        return apps.Select(MapToDto).ToList();
    }

    public async Task<RegisteredApplicationDto?> GetByIdAsync(Guid tenantId, Guid id, CancellationToken ct = default)
    {
        var app = await _dbContext.RegisteredApplications
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.TenantId == tenantId && a.Id == id, ct);

        return app != null ? MapToDto(app) : null;
    }

    public async Task<RegistrationResultDto> RegisterApplicationAsync(
        Guid tenantId,
        RegisterApplicationRequest req,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(req);

        if (string.IsNullOrWhiteSpace(req.ApplicationId))
            throw new ArgumentException("ApplicationId is required.", nameof(req));
        if (string.IsNullOrWhiteSpace(req.AuthorizedTargetUrl))
            throw new ArgumentException("AuthorizedTargetUrl is required.", nameof(req));

        var cleanAppId = req.ApplicationId.Trim();

        // Unique per tenant check
        var exists = await _dbContext.RegisteredApplications
            .AnyAsync(a => a.TenantId == tenantId && a.ApplicationId == cleanAppId, ct);
        if (exists)
        {
            throw new InvalidOperationException($"An application with identifier '{cleanAppId}' already exists for this tenant.");
        }

        // Generate cryptographically random 32-byte secret (64-char hex)
        var secretBytes = new byte[32];
        RandomNumberGenerator.Fill(secretBytes);
        var rawSecret = Convert.ToHexString(secretBytes).ToLowerInvariant();

        var encryptedSecret = _protector.Protect(rawSecret);

        var entity = new RegisteredApplication
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ApplicationId = cleanAppId,
            DisplayName = string.IsNullOrWhiteSpace(req.DisplayName) ? cleanAppId : req.DisplayName.Trim(),
            AuthorizedTargetUrl = req.AuthorizedTargetUrl.Trim(),
            Environment = string.IsNullOrWhiteSpace(req.Environment) ? "Production" : req.Environment.Trim(),
            EncryptedWebhookSecret = encryptedSecret,
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };

        _dbContext.RegisteredApplications.Add(entity);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Registered CI/CD application '{ApplicationId}' ({DisplayName}) for tenant '{TenantId}'.",
            entity.ApplicationId,
            entity.DisplayName,
            tenantId);

        return new RegistrationResultDto(MapToDto(entity), rawSecret);
    }

    public async Task<SecretRotationResultDto> RegenerateSecretAsync(Guid tenantId, Guid id, CancellationToken ct = default)
    {
        var app = await _dbContext.RegisteredApplications
            .FirstOrDefaultAsync(a => a.TenantId == tenantId && a.Id == id, ct);

        if (app == null)
        {
            throw new KeyNotFoundException($"Application with ID '{id}' was not found.");
        }

        var secretBytes = new byte[32];
        RandomNumberGenerator.Fill(secretBytes);
        var newRawSecret = Convert.ToHexString(secretBytes).ToLowerInvariant();

        app.EncryptedWebhookSecret = _protector.Protect(newRawSecret);
        app.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Rotated webhook secret for application '{ApplicationId}' (ID: {Id}) for tenant '{TenantId}'.",
            app.ApplicationId,
            app.Id,
            tenantId);

        return new SecretRotationResultDto(app.Id, app.ApplicationId, newRawSecret);
    }

    public async Task<RegisteredApplicationDto> ToggleStatusAsync(Guid tenantId, Guid id, bool enabled, CancellationToken ct = default)
    {
        var app = await _dbContext.RegisteredApplications
            .FirstOrDefaultAsync(a => a.TenantId == tenantId && a.Id == id, ct);

        if (app == null)
        {
            throw new KeyNotFoundException($"Application with ID '{id}' was not found.");
        }

        app.Enabled = enabled;
        app.UpdatedAtUtc = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Updated application '{ApplicationId}' enabled status to {Enabled} for tenant '{TenantId}'.",
            app.ApplicationId,
            enabled,
            tenantId);

        return MapToDto(app);
    }

    public async Task<bool> DeleteApplicationAsync(Guid tenantId, Guid id, CancellationToken ct = default)
    {
        var app = await _dbContext.RegisteredApplications
            .FirstOrDefaultAsync(a => a.TenantId == tenantId && a.Id == id, ct);

        if (app == null)
        {
            return false;
        }

        _dbContext.RegisteredApplications.Remove(app);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Deleted application '{ApplicationId}' (ID: {Id}) for tenant '{TenantId}'.",
            app.ApplicationId,
            app.Id,
            tenantId);

        return true;
    }

    private static RegisteredApplicationDto MapToDto(RegisteredApplication a) =>
        new(
            a.Id,
            a.ApplicationId,
            a.DisplayName,
            a.AuthorizedTargetUrl,
            a.Environment,
            a.Enabled,
            a.CreatedAtUtc,
            a.UpdatedAtUtc);
}
