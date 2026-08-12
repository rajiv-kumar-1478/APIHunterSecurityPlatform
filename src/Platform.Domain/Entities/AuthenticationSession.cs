namespace Platform.Domain.Entities;

/// <summary>
/// Tracks active and revoked user sessions.
/// Enables admin to revoke all sessions and password-change invalidation.
/// </summary>
public class AuthenticationSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;

    public bool IsRevoked => RevokedAtUtc.HasValue;
    public bool IsExpired => DateTime.UtcNow > ExpiresAtUtc;
    public bool IsValid => !IsRevoked && !IsExpired;

    // Navigation
    public User User { get; set; } = null!;
}
