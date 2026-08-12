using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Persistence;

/// <summary>
/// Seeds the default admin user and permission catalog on startup.
/// Idempotent — safe to call multiple times.
/// </summary>
public class DatabaseSeeder(
    IPlatformDbContext db,
    IPasswordHasher<User> passwordHasher,
    IOptions<SeedOptions> seedOptions,
    ILogger<DatabaseSeeder> logger)
{
    public async Task SeedAsync(CancellationToken ct = default)
    {
        await SeedPermissionsAsync(ct);
        await SeedAdminUserAsync(ct);
        await SeedDefaultSystemSettingsAsync(ct);
    }

    private async Task SeedPermissionsAsync(CancellationToken ct)
    {
        var catalogPermissions = PermissionCatalog.GetAll();

        foreach (var (code, name, category, description) in catalogPermissions)
        {
            if (!await db.Permissions.AnyAsync(p => p.Code == code, ct))
            {
                db.Permissions.Add(new Permission
                {
                    Code = code,
                    Name = name,
                    Category = category,
                    Description = description
                });
                logger.LogDebug("Seeded permission: {Code}", code);
            }
        }

        await db.SaveChangesAsync(ct);
        logger.LogInformation("Permission catalog seeded");
    }

    private async Task SeedAdminUserAsync(CancellationToken ct)
    {
        var opts = seedOptions.Value;
        if (string.IsNullOrWhiteSpace(opts.AdminEmail) || string.IsNullOrWhiteSpace(opts.AdminPassword))
        {
            logger.LogWarning("ADMIN_EMAIL or ADMIN_PASSWORD not set. Skipping admin seed.");
            return;
        }

        if (await db.Users.AnyAsync(u => u.IsPlatformAdmin, ct))
        {
            logger.LogDebug("Admin user already exists. Skipping seed.");
            return;
        }

        var admin = new User
        {
            Email = opts.AdminEmail.ToLower(),
            Username = "admin",
            DisplayName = "Platform Admin",
            IsPlatformAdmin = true,
            IsActive = true
        };
        admin.PasswordHash = passwordHasher.HashPassword(admin, opts.AdminPassword);

        db.Users.Add(admin);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Admin user seeded: {Email}", opts.AdminEmail);
    }

    private async Task SeedDefaultSystemSettingsAsync(CancellationToken ct)
    {
        var defaults = new[]
        {
            ("EMAIL_ALERTS_ENABLED", "false", SettingValueType.Boolean, false, "Enable email alerts for findings"),
            ("MAX_SESSIONS_PER_USER", "10", SettingValueType.Integer, false, "Maximum concurrent sessions per user"),
        };

        foreach (var (key, value, type, isSecret, desc) in defaults)
        {
            if (!await db.SystemSettings.AnyAsync(s => s.Key == key, ct))
            {
                db.SystemSettings.Add(new SystemSetting
                {
                    Key = key,
                    Value = value,
                    ValueType = type,
                    IsSecret = isSecret,
                    Description = desc
                });
            }
        }

        await db.SaveChangesAsync(ct);
    }
}

public class SeedOptions
{
    public const string SectionName = "Seed";
    public string AdminEmail { get; set; } = string.Empty;
    public string AdminPassword { get; set; } = string.Empty;
}

/// <summary>
/// Canonical permission code catalog. Single source of truth.
/// </summary>
public static class PermissionCatalog
{
    public static IEnumerable<(string Code, string Name, string Category, string Description)> GetAll()
    {
        yield return ("dashboard.view", "View Dashboard", "Dashboard", "Access the main dashboard");
        yield return ("users.view", "View Users", "User Management", "View user list");
        yield return ("users.manage", "Manage Users", "User Management", "Create, update, disable users");
        yield return ("permissions.view", "View Permissions", "Permissions", "View permission assignments");
        yield return ("permissions.manage", "Manage Permissions", "Permissions", "Grant and revoke permissions");
        yield return ("audit.view", "View Audit Log", "Audit", "Access the audit event log");
        yield return ("health.view", "View Health Status", "Operations", "View system health");
        yield return ("health.detailed", "View Detailed Health", "Operations", "View detailed component health");
        yield return ("notifications.manage", "Manage Notifications", "Notifications", "Configure notification providers");
        yield return ("settings.view", "View Settings", "Settings", "View system settings");
        yield return ("settings.manage", "Manage Settings", "Settings", "Modify system settings");
        // Phase 2+ placeholders
        yield return ("credential.view", "View Credentials", "Credentials", "View discovered credentials (masked)");
        yield return ("credential.reveal", "Reveal Credentials", "Credentials", "View unmasked credential values");
        yield return ("repo.view", "View Repositories", "Intelligence", "View repository analysis");
        yield return ("findings.view", "View Findings", "Security", "View security findings");
    }
}
