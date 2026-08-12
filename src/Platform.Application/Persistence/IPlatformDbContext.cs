using Microsoft.EntityFrameworkCore;
using Platform.Domain.Entities;

namespace Platform.Application.Persistence;

/// <summary>
/// Application-layer abstraction for the platform database.
/// Infrastructure provides the EF Core implementation.
/// </summary>
public interface IPlatformDbContext
{
    DbSet<User> Users { get; }
    DbSet<AuthenticationSession> AuthenticationSessions { get; }
    DbSet<Permission> Permissions { get; }
    DbSet<UserPermission> UserPermissions { get; }
    DbSet<FieldPermission> FieldPermissions { get; }
    DbSet<AuditEvent> AuditEvents { get; }
    DbSet<NotificationProviderConfig> NotificationProviderConfigs { get; }
    DbSet<SystemSetting> SystemSettings { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
