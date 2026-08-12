using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Stores encrypted configuration for a notification provider.
/// ConfigurationEncrypted uses ASP.NET Core Data Protection.
/// Plaintext credentials are NEVER stored.
/// </summary>
public class NotificationProviderConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public NotificationChannel Channel { get; set; }
    public NotificationProviderType Provider { get; set; }
    public bool Enabled { get; set; }

    /// <summary>
    /// JSON configuration encrypted with ASP.NET Core Data Protection.
    /// Never contains plaintext secrets.
    /// </summary>
    public string ConfigurationEncrypted { get; set; } = string.Empty;

    /// <summary>
    /// Lower number = higher priority. Used when multiple providers for same channel.
    /// </summary>
    public int Priority { get; set; } = 1;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
