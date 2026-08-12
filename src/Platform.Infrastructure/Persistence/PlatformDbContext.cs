using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Persistence;

public class PlatformDbContext(DbContextOptions<PlatformDbContext> options)
    : DbContext(options), IPlatformDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<AuthenticationSession> AuthenticationSessions => Set<AuthenticationSession>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();
    public DbSet<FieldPermission> FieldPermissions => Set<FieldPermission>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<NotificationProviderConfig> NotificationProviderConfigs => Set<NotificationProviderConfig>();
    public DbSet<SystemSetting> SystemSettings => Set<SystemSetting>();
    public DbSet<ApiHunterRecord> ApiHunterRecords => Set<ApiHunterRecord>();
    public DbSet<ApiHunterRepoReference> ApiHunterRepoReferences => Set<ApiHunterRepoReference>();
    public DbSet<ApiHunterSyncState> ApiHunterSyncStates => Set<ApiHunterSyncState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User
        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(u => u.Id);
            e.HasIndex(u => u.Email).IsUnique();
            e.HasIndex(u => u.Username).IsUnique();
            e.Property(u => u.Email).HasMaxLength(256).IsRequired();
            e.Property(u => u.Username).HasMaxLength(100).IsRequired();
            e.Property(u => u.DisplayName).HasMaxLength(200).IsRequired();
            e.Property(u => u.PasswordHash).IsRequired();
        });

        // AuthenticationSession
        modelBuilder.Entity<AuthenticationSession>(e =>
        {
            e.ToTable("authentication_sessions");
            e.HasKey(s => s.Id);
            e.HasIndex(s => s.SessionId).IsUnique();
            e.HasIndex(s => new { s.UserId, s.ExpiresAtUtc });
            e.HasOne(s => s.User).WithMany(u => u.Sessions).HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // Permission
        modelBuilder.Entity<Permission>(e =>
        {
            e.ToTable("permissions");
            e.HasKey(p => p.Id);
            e.HasIndex(p => p.Code).IsUnique();
            e.Property(p => p.Code).HasMaxLength(100).IsRequired();
            e.Property(p => p.Name).HasMaxLength(200).IsRequired();
            e.Property(p => p.Category).HasMaxLength(100).IsRequired();
        });

        // UserPermission
        modelBuilder.Entity<UserPermission>(e =>
        {
            e.ToTable("user_permissions");
            e.HasKey(up => new { up.UserId, up.PermissionId });
            e.HasOne(up => up.User).WithMany(u => u.UserPermissions).HasForeignKey(up => up.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(up => up.Permission).WithMany(p => p.UserPermissions).HasForeignKey(up => up.PermissionId).OnDelete(DeleteBehavior.Cascade);
        });

        // FieldPermission
        modelBuilder.Entity<FieldPermission>(e =>
        {
            e.ToTable("field_permissions");
            e.HasKey(fp => fp.Id);
            e.HasIndex(fp => new { fp.PermissionCode, fp.ResourceType, fp.FieldName, fp.Action }).IsUnique();
            e.Property(fp => fp.PermissionCode).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.ResourceType).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.FieldName).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.Effect).HasConversion<string>();
            e.Property(fp => fp.Action).HasConversion<string>();
        });

        // AuditEvent
        modelBuilder.Entity<AuditEvent>(e =>
        {
            e.ToTable("audit_events");
            e.HasKey(a => a.Id);
            e.HasIndex(a => a.UserId);
            e.HasIndex(a => a.CorrelationId);
            e.HasIndex(a => a.CreatedAtUtc);
            e.Property(a => a.EventCode).HasConversion<string>().HasMaxLength(100);
            e.Property(a => a.Metadata).HasColumnType("jsonb");
            e.HasOne(a => a.User).WithMany(u => u.AuditEvents).HasForeignKey(a => a.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        // NotificationProviderConfig
        modelBuilder.Entity<NotificationProviderConfig>(e =>
        {
            e.ToTable("notification_provider_configs");
            e.HasKey(n => n.Id);
            e.Property(n => n.Channel).HasConversion<string>();
            e.Property(n => n.Provider).HasConversion<string>();
        });

        // SystemSetting
        modelBuilder.Entity<SystemSetting>(e =>
        {
            e.ToTable("system_settings");
            e.HasKey(s => s.Key);
            e.Property(s => s.ValueType).HasConversion<string>();
        });

        // ApiHunterRecord
        modelBuilder.Entity<ApiHunterRecord>(e =>
        {
            e.ToTable("api_hunter_records");
            e.HasKey(r => r.Id);
            e.HasIndex(r => r.SourceRecordId).IsUnique();
            e.HasIndex(r => new { r.Status, r.ApiType });
            e.Property(r => r.Status).HasConversion<int>();
        });

        // ApiHunterRepoReference
        modelBuilder.Entity<ApiHunterRepoReference>(e =>
        {
            e.ToTable("api_hunter_repo_references");
            e.HasKey(rr => rr.Id);
            e.HasIndex(rr => rr.SourceReferenceId).IsUnique();
            e.HasIndex(rr => new { rr.RepoOwner, rr.RepoName });
            e.HasOne(rr => rr.ApiHunterRecord)
             .WithMany(r => r.RepoReferences)
             .HasForeignKey(rr => rr.ApiHunterRecordId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ApiHunterSyncState
        modelBuilder.Entity<ApiHunterSyncState>(e =>
        {
            e.ToTable("api_hunter_sync_states");
            e.HasKey(s => s.Id);
            e.Property(s => s.Status).HasConversion<string>();
        });
    }
}
