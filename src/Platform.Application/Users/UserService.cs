using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Users;

public record CreateUserCommand(string Email, string Username, string DisplayName, string Password, bool IsPlatformAdmin);
public record UpdateUserCommand(Guid Id, string? DisplayName, bool? IsActive, bool? IsPlatformAdmin);
public record UserDto(Guid Id, string Email, string Username, string DisplayName, bool IsPlatformAdmin, bool IsActive, DateTime CreatedAtUtc, DateTime? LastLoginAtUtc);

public class UserService(
    IPlatformDbContext db,
    IPasswordHasher<User> passwordHasher,
    IAuditService auditService,
    ICurrentUserContext currentUser)
{
    public async Task<Result<UserDto>> CreateUserAsync(CreateUserCommand command, CancellationToken ct = default)
    {
        if (await db.Users.AnyAsync(u => u.Email.ToLower() == command.Email.ToLower(), ct))
            return Result<UserDto>.Failure("Email already registered", "EMAIL_TAKEN");

        var user = new User
        {
            Email = command.Email.ToLower().Trim(),
            Username = command.Username.Trim(),
            DisplayName = command.DisplayName.Trim(),
            IsPlatformAdmin = command.IsPlatformAdmin
        };
        user.PasswordHash = passwordHasher.HashPassword(user, command.Password);

        db.Users.Add(user);
        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.UserCreated,
            currentUser.UserId, null, currentUser.IpAddress,
            new { userId = user.Id, email = user.Email, isPlatformAdmin = user.IsPlatformAdmin }, ct);

        return Result<UserDto>.Success(ToDto(user));
    }

    public async Task<Result<UserDto>> UpdateUserAsync(UpdateUserCommand command, CancellationToken ct = default)
    {
        var user = await db.Users.FindAsync([command.Id], ct);
        if (user is null) return Result<UserDto>.Failure("User not found", "NOT_FOUND");

        var changes = new Dictionary<string, object?>();

        if (command.DisplayName is not null && command.DisplayName != user.DisplayName)
        {
            changes["displayName"] = new { from = user.DisplayName, to = command.DisplayName };
            user.DisplayName = command.DisplayName;
        }

        if (command.IsActive.HasValue && command.IsActive.Value != user.IsActive)
        {
            changes["isActive"] = new { from = user.IsActive, to = command.IsActive.Value };
            user.IsActive = command.IsActive.Value;
        }

        if (command.IsPlatformAdmin.HasValue && command.IsPlatformAdmin.Value != user.IsPlatformAdmin)
        {
            changes["isPlatformAdmin"] = new { from = user.IsPlatformAdmin, to = command.IsPlatformAdmin.Value };
            user.IsPlatformAdmin = command.IsPlatformAdmin.Value;
        }

        user.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        var eventCode = command.IsActive == false ? AuditEventCode.UserDisabled
                      : command.IsActive == true  ? AuditEventCode.UserEnabled
                      : AuditEventCode.UserUpdated;

        await auditService.RecordAsync(eventCode,
            currentUser.UserId, null, currentUser.IpAddress,
            new { targetUserId = command.Id, changes }, ct);

        return Result<UserDto>.Success(ToDto(user));
    }

    public async Task<PagedResult<UserDto>> GetUsersAsync(PaginationRequest pagination, CancellationToken ct = default)
    {
        var total = await db.Users.CountAsync(ct);
        var users = await db.Users
            .OrderByDescending(u => u.CreatedAtUtc)
            .Skip(pagination.Skip)
            .Take(pagination.Take)
            .ToListAsync(ct);

        return new PagedResult<UserDto>(users.Select(ToDto).ToList(), total, pagination.Page, pagination.PageSize);
    }

    public async Task<UserDto?> GetUserByIdAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await db.Users.FindAsync([userId], ct);
        return user is null ? null : ToDto(user);
    }

    private static UserDto ToDto(User u) => new(
        u.Id, u.Email, u.Username, u.DisplayName,
        u.IsPlatformAdmin, u.IsActive, u.CreatedAtUtc, u.LastLoginAtUtc);
}
