using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Permissions;

public record PermissionDto(Guid Id, string Code, string Name, string Category, string Description);
public record UserPermissionDto(string PermissionCode, bool Enabled);
public record FieldPermissionDto(Guid Id, string PermissionCode, string ResourceType, string FieldName, string Action, string Effect);
public record GrantPermissionsCommand(Guid UserId, List<string> PermissionCodes);
public record UpsertFieldPermissionCommand(string PermissionCode, string ResourceType, string FieldName, FieldAction Action, PermissionEffect Effect);

public class PermissionService(
    IPlatformDbContext db,
    IAuditService auditService,
    ICurrentUserContext currentUser)
{
    /// <summary>
    /// Returns permissions available to the caller for UI rendering.
    /// Non-admins only see their own permissions.
    /// </summary>
    public async Task<List<PermissionDto>> GetCallerPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        var perms = await db.UserPermissions
            .Include(up => up.Permission)
            .Where(up => up.UserId == userId && up.Enabled)
            .Select(up => up.Permission)
            .ToListAsync(ct);

        return perms.Select(p => new PermissionDto(p.Id, p.Code, p.Name, p.Category, p.Description)).ToList();
    }

    /// <summary>
    /// Admin: Returns the full permission catalog.
    /// </summary>
    public async Task<List<PermissionDto>> GetAllPermissionsAsync(CancellationToken ct = default)
    {
        var perms = await db.Permissions.OrderBy(p => p.Category).ThenBy(p => p.Name).ToListAsync(ct);
        return perms.Select(p => new PermissionDto(p.Id, p.Code, p.Name, p.Category, p.Description)).ToList();
    }

    /// <summary>
    /// Admin: Get permissions for a specific user.
    /// </summary>
    public async Task<List<UserPermissionDto>> GetUserPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        var grants = await db.UserPermissions
            .Include(up => up.Permission)
            .Where(up => up.UserId == userId)
            .ToListAsync(ct);

        return grants.Select(up => new UserPermissionDto(up.Permission.Code, up.Enabled)).ToList();
    }

    /// <summary>
    /// Admin: Grant/revoke permissions for a user.
    /// </summary>
    public async Task<Result> SetUserPermissionsAsync(GrantPermissionsCommand command, CancellationToken ct = default)
    {
        var permissions = await db.Permissions
            .Where(p => command.PermissionCodes.Contains(p.Code))
            .ToListAsync(ct);

        var existingGrants = await db.UserPermissions
            .Where(up => up.UserId == command.UserId)
            .ToListAsync(ct);

        // Remove all existing, re-add
        db.UserPermissions.RemoveRange(existingGrants);

        foreach (var perm in permissions)
        {
            db.UserPermissions.Add(new UserPermission
            {
                UserId = command.UserId,
                PermissionId = perm.Id,
                Enabled = true,
                GrantedByUserId = currentUser.UserId ?? Guid.Empty
            });
        }

        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.PermissionGranted,
            currentUser.UserId, null, currentUser.IpAddress,
            new { targetUserId = command.UserId, permissions = command.PermissionCodes }, ct);

        return Result.Success();
    }

    /// <summary>
    /// Check if a user has a permission code.
    /// IsPlatformAdmin always returns true without checking permission rows.
    /// </summary>
    public async Task<bool> HasPermissionAsync(Guid userId, string permissionCode, CancellationToken ct = default)
    {
        var user = await db.Users.FindAsync([userId], ct);
        if (user is null) return false;
        if (user.IsPlatformAdmin) return true;  // Admin bypass

        return await db.UserPermissions
            .Include(up => up.Permission)
            .AnyAsync(up => up.UserId == userId
                         && up.Permission.Code == permissionCode
                         && up.Enabled, ct);
    }

    /// <summary>
    /// Evaluate field-level access for a user on a given resource field.
    /// Returns false if any DENY rule matches, or if no ALLOW rule matches.
    /// </summary>
    public async Task<bool> CanAccessFieldAsync(
        Guid userId, string resourceType, string fieldName,
        FieldAction action, CancellationToken ct = default)
    {
        var user = await db.Users.FindAsync([userId], ct);
        if (user is null) return false;
        if (user.IsPlatformAdmin) return true;  // Admin bypass

        var userPermCodes = await db.UserPermissions
            .Include(up => up.Permission)
            .Where(up => up.UserId == userId && up.Enabled)
            .Select(up => up.Permission.Code)
            .ToListAsync(ct);

        var fieldRules = await db.FieldPermissions
            .Where(fp => fp.ResourceType == resourceType
                      && fp.FieldName == fieldName
                      && fp.Action == action
                      && userPermCodes.Contains(fp.PermissionCode))
            .ToListAsync(ct);

        // Explicit DENY wins
        if (fieldRules.Any(r => r.Effect == PermissionEffect.Deny))
            return false;

        // Requires at least one ALLOW
        return fieldRules.Any(r => r.Effect == PermissionEffect.Allow);
    }

    public async Task<List<FieldPermissionDto>> GetFieldPermissionsAsync(CancellationToken ct = default)
    {
        var rules = await db.FieldPermissions.ToListAsync(ct);
        return rules.Select(r => new FieldPermissionDto(
            r.Id, r.PermissionCode, r.ResourceType, r.FieldName,
            r.Action.ToString(), r.Effect.ToString())).ToList();
    }

    public async Task<Result> UpsertFieldPermissionAsync(UpsertFieldPermissionCommand command, CancellationToken ct = default)
    {
        var existing = await db.FieldPermissions.FirstOrDefaultAsync(
            fp => fp.PermissionCode == command.PermissionCode
               && fp.ResourceType == command.ResourceType
               && fp.FieldName == command.FieldName
               && fp.Action == command.Action, ct);

        if (existing is null)
        {
            db.FieldPermissions.Add(new FieldPermission
            {
                PermissionCode = command.PermissionCode,
                ResourceType = command.ResourceType,
                FieldName = command.FieldName,
                Action = command.Action,
                Effect = command.Effect
            });
        }
        else
        {
            existing.Effect = command.Effect;
        }

        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.FieldPermissionChanged,
            currentUser.UserId, null, currentUser.IpAddress,
            new { permissionCode = command.PermissionCode, resourceType = command.ResourceType,
                  fieldName = command.FieldName, effect = command.Effect }, ct);

        return Result.Success();
    }
}
