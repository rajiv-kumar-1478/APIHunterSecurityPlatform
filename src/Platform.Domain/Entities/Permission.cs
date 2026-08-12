namespace Platform.Domain.Entities;

/// <summary>
/// A permission code that can be granted to users.
/// IsPlatformAdmin bypasses all permission checks.
/// </summary>
public class Permission
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Unique code. E.g. "dashboard.view", "credential.reveal", "user.manage"
    /// </summary>
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    // Navigation
    public ICollection<UserPermission> UserPermissions { get; set; } = [];
    public ICollection<FieldPermission> FieldPermissions { get; set; } = [];
}
