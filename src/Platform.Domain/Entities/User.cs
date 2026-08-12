namespace Platform.Domain.Entities;

/// <summary>
/// Platform user. IsPlatformAdmin bypasses all permission checks.
/// </summary>
public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// True = full platform admin. Bypasses normal permission checks.
    /// Audit records every admin action.
    /// </summary>
    public bool IsPlatformAdmin { get; set; }

    public bool IsActive { get; set; } = true;
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutUntilUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAtUtc { get; set; }

    // Navigation
    public ICollection<AuthenticationSession> Sessions { get; set; } = [];
    public ICollection<UserPermission> UserPermissions { get; set; } = [];
    public ICollection<AuditEvent> AuditEvents { get; set; } = [];
}
