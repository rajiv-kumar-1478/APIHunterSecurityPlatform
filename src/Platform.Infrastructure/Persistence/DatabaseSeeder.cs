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
        await SeedDetectionRulesAsync(ct);
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

    private async Task SeedDetectionRulesAsync(CancellationToken ct)
    {
        var rules = BuiltInDetectionRules.GetRules();

        foreach (var rule in rules)
        {
            if (!await db.DetectionRules.AnyAsync(r => r.Id == rule.Id && r.Version == rule.Version, ct))
            {
                db.DetectionRules.Add(rule);
                logger.LogDebug("Seeded detection rule: {Id} v{Version}", rule.Id, rule.Version);
            }
        }

        await db.SaveChangesAsync(ct);
        logger.LogInformation("Seeded built-in secret detection rules");
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

        // Phase 3 Permissions
        yield return ("repository.view", "View Repositories", "Repositories", "View repository list and metadata");
        yield return ("repository.manage", "Manage Repositories", "Repositories", "Add repositories and trigger acquisition");
        yield return ("candidate.view", "View Secret Candidates", "Candidates", "View masked secret candidates and occurrences");
        yield return ("candidate.reveal", "Reveal Raw Secret Candidate", "Candidates", "Reveal unmasked raw secret values (Audited)");
        yield return ("candidate.manage", "Manage Secret Candidates", "Candidates", "Update triage status and resolve candidates");
        yield return ("job.view", "View Analysis Jobs", "Jobs", "Monitor analysis job queue");
        yield return ("job.manage", "Manage Analysis Jobs", "Jobs", "Cancel, retry, or pause analysis jobs");
        yield return ("rule.view", "View Detection Rules", "Rules", "View secret detection rules");
        yield return ("rule.manage", "Manage Detection Rules", "Rules", "Create or toggle secret detection rules");
    }
}

public static class BuiltInDetectionRules
{
    public static List<DetectionRule> GetRules()
    {
        return new List<DetectionRule>
        {
            new() { Id = "openai-api-key", Version = 1, Description = "OpenAI API Key", RegexPattern = @"sk-[A-Za-z0-9\-]{20,}", CredentialType = "OpenAI", Confidence = "High" },
            new() { Id = "openai-proj-key", Version = 1, Description = "OpenAI Project Key", RegexPattern = @"sk-proj-[A-Za-z0-9\-]{20,}", CredentialType = "OpenAI", Confidence = "High" },
            new() { Id = "anthropic-api-key", Version = 1, Description = "Anthropic Claude Key", RegexPattern = @"sk-ant-[a-zA-Z0-9\-_]{20,120}", CredentialType = "Anthropic", Confidence = "High" },
            new() { Id = "aws-access-key-id", Version = 1, Description = "AWS Access Key ID", RegexPattern = @"\b(AKIA|ASIA)[0-9A-Z]{16}\b", CredentialType = "AWSIAM", Confidence = "High" },
            new() { Id = "aws-secret-access-key", Version = 1, Description = "AWS Secret Access Key", RegexPattern = @"(?i)aws_secret_access_key\s*[:=]\s*['""]?([A-Za-z0-9/+=]{40})['""]?", CredentialType = "AWSIAM", Confidence = "High" },
            new() { Id = "github-pat", Version = 1, Description = "GitHub Personal Access Token", RegexPattern = @"ghp_[a-zA-Z0-9_-]{36}", CredentialType = "GitHub", Confidence = "High" },
            new() { Id = "github-fine-grained-pat", Version = 1, Description = "GitHub Fine-Grained PAT", RegexPattern = @"github_pat_[a-zA-Z0-9_-]{22,}", CredentialType = "GitHub", Confidence = "High" },
            new() { Id = "github-oauth-token", Version = 1, Description = "GitHub OAuth Access Token", RegexPattern = @"gho_[a-zA-Z0-9_-]{36}", CredentialType = "GitHub", Confidence = "High" },
            new() { Id = "stripe-secret-key", Version = 1, Description = "Stripe Secret Key", RegexPattern = @"sk_live_[0-9a-zA-Z]{24,}", CredentialType = "Stripe", Confidence = "High" },
            new() { Id = "stripe-restricted-key", Version = 1, Description = "Stripe Restricted Key", RegexPattern = @"rk_live_[0-9a-zA-Z]{24,}", CredentialType = "Stripe", Confidence = "High" },
            new() { Id = "sendgrid-api-key", Version = 1, Description = "SendGrid API Key", RegexPattern = @"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", CredentialType = "SendGrid", Confidence = "High" },
            new() { Id = "mailgun-api-key", Version = 1, Description = "Mailgun API Key", RegexPattern = @"key-[0-9a-zA-Z]{32}", CredentialType = "Mailgun", Confidence = "High" },
            new() { Id = "huggingface-token", Version = 1, Description = "HuggingFace Token", RegexPattern = @"hf_[a-zA-Z0-9]{34}", CredentialType = "HuggingFace", Confidence = "High" },
            new() { Id = "perplexity-api-key", Version = 1, Description = "Perplexity API Key", RegexPattern = @"pplx-[a-zA-Z0-9]{48}", CredentialType = "Perplexity", Confidence = "High" },
            new() { Id = "groq-api-key", Version = 1, Description = "Groq API Key", RegexPattern = @"gsk_[a-zA-Z0-9]{48}", CredentialType = "Groq", Confidence = "High" },
            new() { Id = "cohere-api-key", Version = 1, Description = "Cohere API Key", RegexPattern = @"[a-zA-Z0-9]{40}", CredentialType = "Cohere", Confidence = "Medium" },
            new() { Id = "deepseek-api-key", Version = 1, Description = "DeepSeek API Key", RegexPattern = @"sk-[a-f0-9]{32}", CredentialType = "DeepSeek", Confidence = "High" },
            new() { Id = "fireworks-api-key", Version = 1, Description = "Fireworks AI Key", RegexPattern = @"fw_[A-Za-z0-9_-]{30,80}", CredentialType = "FireworksAI", Confidence = "High" },
            new() { Id = "replicate-api-key", Version = 1, Description = "Replicate API Key", RegexPattern = @"r8_[a-zA-Z0-9]{32}", CredentialType = "Replicate", Confidence = "High" },
            new() { Id = "slack-bot-token", Version = 1, Description = "Slack Bot Token", RegexPattern = @"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}", CredentialType = "Slack", Confidence = "High" }
        };
    }
}

