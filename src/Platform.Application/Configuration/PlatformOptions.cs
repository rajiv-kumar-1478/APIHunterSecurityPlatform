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
