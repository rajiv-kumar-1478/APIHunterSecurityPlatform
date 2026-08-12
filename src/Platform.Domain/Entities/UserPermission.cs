namespace Platform.Domain.Entities;

public class UserPermission
{
    public Guid UserId { get; set; }
    public Guid PermissionId { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime GrantedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid GrantedByUserId { get; set; }

    // Navigation
    public User User { get; set; } = null!;
    public Permission Permission { get; set; } = null!;
}
