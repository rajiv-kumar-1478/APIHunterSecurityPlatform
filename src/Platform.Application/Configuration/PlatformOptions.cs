namespace Platform.Application.Configuration;

/// <summary>
/// Strongly-typed authentication options. Never use Environment.GetEnvironmentVariable directly.
/// </summary>
public class AuthenticationOptions
{
    public const string SectionName = "Authentication";

    public int SessionDurationMinutes { get; set; } = 480;       // 8 hours
    public int LockoutThreshold { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 15;
    public int MaxConcurrentSessions { get; set; } = 10;
    public bool RequireHttps { get; set; } = true;
}

public class TenantOptions
{
    public const string SectionName = "Tenant";
    public Guid Id { get; set; }
}

public class DatabaseOptions
{
    public const string SectionName = "Database";
    public string ConnectionString { get; set; } = string.Empty;
}

public class CorsOptions
{
    public const string SectionName = "Cors";
    public string[] AllowedOrigins { get; set; } = [];
}

public class DataProtectionOptions
{
    public const string SectionName = "DataProtection";
    public string? KeyPath { get; set; }
    public string ApplicationName { get; set; } = "APIHunterPlatform";
}

public class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";
    public int LoginMaxAttempts { get; set; } = 5;
    public int LoginWindowSeconds { get; set; } = 300;
    public int ApiMaxRequestsPerMinute { get; set; } = 300;
}

public class NotificationOptions
{
    public const string SectionName = "Notification";

    /// <summary>Email provider: smtp | sendgrid | mailgun</summary>
    public string EmailProvider { get; set; } = "smtp";
}

public class SmtpOptions
{
    public const string SectionName = "Smtp";
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string From { get; set; } = string.Empty;
    public bool UseTls { get; set; } = true;
}

public class SendGridOptions
{
    public const string SectionName = "SendGrid";
    public string ApiKey { get; set; } = string.Empty;
    public string From { get; set; } = string.Empty;
}

public class MailgunOptions
{
    public const string SectionName = "Mailgun";
    public string ApiKey { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;

    /// <summary>us | eu</summary>
    public string Region { get; set; } = "us";
    public string From { get; set; } = string.Empty;

    public string BaseUrl => Region.ToLower() == "eu"
        ? "https://api.eu.mailgun.net"
        : "https://api.mailgun.net";
}

public class ApiHunterSourceOptions
{
    public const string SectionName = "ApiHunterSource";
    public string ConnectionString { get; set; } = string.Empty;
    public bool AutoSyncEnabled { get; set; } = true;
    public int BatchSize { get; set; } = 1000;
}

public class VpsSshOptions
{
    public const string SectionName = "VpsSsh";

    /// <summary>Enables SSH-based database tunneling and repository download on the VPS.</summary>
    public bool Enabled { get; set; }

    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 22;
    public string Username { get; set; } = "ubuntu";

    /// <summary>Absolute path to the private key. Never commit the key itself.</summary>
    public string PrivateKeyPath { get; set; } = string.Empty;
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>Expected SHA256 host-key fingerprint, e.g. "SHA256:abc...". Strongly recommended.</summary>
    public string HostKeyFingerprint { get; set; } = string.Empty;

    /// <summary>Remote directory used for temporary clones/archives.</summary>
    public string RemoteWorkDir { get; set; } = "/tmp/apihunter-repos";

    public string GitBinaryPath { get; set; } = "git";
    public int ConnectTimeoutSeconds { get; set; } = 30;
    public int CommandTimeoutSeconds { get; set; } = 300;

    /// <summary>Maximum archive size accepted from the VPS (bytes).</summary>
    public long MaxArchiveBytes { get; set; } = 512L * 1024 * 1024;
}

public class GitHubOptions
{
    public const string SectionName = "GitHub";

    /// <summary>"App", "PAT", or "Anonymous"</summary>
    public string AuthType { get; set; } = "Anonymous";

    public long AppId { get; set; }
    public string PrivateKeyPem { get; set; } = string.Empty;
    public long InstallationId { get; set; }
    public string PersonalAccessToken { get; set; } = string.Empty;
    public string UserAgent { get; set; } = "APIHunterPlatform";
}

public class ObjectStoreOptions
{
    public const string SectionName = "ObjectStore";

    /// <summary>"FileSystem" (dev only) or "S3" (production)</summary>
    public string Provider { get; set; } = "FileSystem";
    public string BasePath { get; set; } = "./object-store";
    public string ServiceUrl { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string SecretAccessKey { get; set; } = string.Empty;
    public string BucketName { get; set; } = "apihunter-snapshots";
    public string Region { get; set; } = "auto";
}

public class DetectionOptions
{
    public const string SectionName = "Detection";

    /// <summary>HMAC pepper key for secret fingerprinting</summary>
    public string SecretPepper { get; set; } = "default_dev_secret_pepper_do_not_use_in_prod";
    public int FingerprintKeyVersion { get; set; } = 1;
    public int MaxFileSizeMb { get; set; } = 5;
    public int RegexTimeoutSeconds { get; set; } = 2;
    public int MaxMatchesPerFile { get; set; } = 100;
    public int MaxHistoricalCommitsPerRepository { get; set; } = 25;
    public int RawContextRetentionDays { get; set; } = 30;
}

