using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Application.Persistence;
using Platform.Application.Configuration;

namespace Platform.Application.Auth;

public record LoginCommand(string Email, string Password, string IpAddress, string UserAgent);
public record LoginResult(Guid SessionId, string SessionToken, DateTime ExpiresAtUtc, bool IsPlatformAdmin);
public record SessionDto(Guid Id, string IpAddress, string UserAgent, DateTime CreatedAtUtc, DateTime LastSeenAtUtc, bool IsCurrent);

public class AuthService(
    IPlatformDbContext db,
    IPasswordHasher<User> passwordHasher,
    IAuditService auditService,
    ICurrentUserContext currentUser,
    IOptions<AuthenticationOptions> authOptions,
    ILogger<AuthService> logger)
{
    private readonly AuthenticationOptions _authOpts = authOptions.Value;

    public async Task<Result<LoginResult>> LoginAsync(LoginCommand command, CancellationToken ct = default)
    {
        var user = await db.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == command.Email.ToLower(), ct);

        if (user is null)
        {
            logger.LogWarning("Login attempt for unknown email from {Ip}", command.IpAddress);
            await auditService.RecordAsync(AuditEventCode.UserLoginFailed, null, null,
                command.IpAddress, new { reason = "user_not_found", email = command.Email }, ct);
            return Result<LoginResult>.Failure("Invalid credentials", "INVALID_CREDENTIALS");
        }

        // Check lockout
        if (user.LockoutUntilUtc.HasValue && user.LockoutUntilUtc.Value > DateTime.UtcNow)
        {
            logger.LogWarning("Login attempt for locked account {UserId}", user.Id);
            await auditService.RecordAsync(AuditEventCode.UserLoginFailed, user.Id, null,
                command.IpAddress, new { reason = "account_locked" }, ct);
            return Result<LoginResult>.Failure("Account temporarily locked. Please try again later.", "ACCOUNT_LOCKED");
        }

        if (!user.IsActive)
        {
            return Result<LoginResult>.Failure("Account is disabled.", "ACCOUNT_DISABLED");
        }

        var verification = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, command.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            user.FailedLoginCount++;
            if (user.FailedLoginCount >= _authOpts.LockoutThreshold)
            {
                user.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(_authOpts.LockoutDurationMinutes);
                user.FailedLoginCount = 0;
                logger.LogWarning("Account {UserId} locked after {Attempts} failed attempts", user.Id, _authOpts.LockoutThreshold);
                await auditService.RecordAsync(AuditEventCode.UserLocked, user.Id, null,
                    command.IpAddress, new { attempts = _authOpts.LockoutThreshold }, ct);
            }
            else
            {
                await auditService.RecordAsync(AuditEventCode.UserLoginFailed, user.Id, null,
                    command.IpAddress, new { reason = "invalid_password", attempt = user.FailedLoginCount }, ct);
            }
            await db.SaveChangesAsync(ct);
            return Result<LoginResult>.Failure("Invalid credentials", "INVALID_CREDENTIALS");
        }

        // Successful login
        user.FailedLoginCount = 0;
        user.LockoutUntilUtc = null;
        user.LastLoginAtUtc = DateTime.UtcNow;

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = passwordHasher.HashPassword(user, command.Password);
        }

        var session = new AuthenticationSession
        {
            SessionId = Guid.NewGuid().ToString("N"),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(_authOpts.SessionDurationMinutes),
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent
        };

        db.AuthenticationSessions.Add(session);
        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.UserLogin, user.Id, session.Id,
            command.IpAddress, new { sessionId = session.Id }, ct);

        logger.LogInformation("User {UserId} logged in from {Ip}", user.Id, command.IpAddress);

        return Result<LoginResult>.Success(new LoginResult(
            session.Id,
            session.SessionId,
            session.ExpiresAtUtc,
            user.IsPlatformAdmin));
    }

    public async Task<Result> LogoutAsync(Guid sessionId, CancellationToken ct = default)
    {
        var session = await db.AuthenticationSessions.FindAsync([sessionId], ct);
        if (session is null) return Result.Success();

        session.RevokedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.UserLogout,
            currentUser.UserId, sessionId,
            currentUser.IpAddress, new { sessionId }, ct);

        return Result.Success();
    }

    public async Task<Result> RevokeSessionAsync(Guid sessionId, CancellationToken ct = default)
    {
        var session = await db.AuthenticationSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.Id == sessionId, ct);

        if (session is null)
            return Result.Failure("Session not found", "NOT_FOUND");

        // Users can only revoke their own sessions. Admins can revoke any.
        if (!currentUser.IsPlatformAdmin && session.UserId != currentUser.UserId)
            return Result.Failure("Access denied", "ACCESS_DENIED");

        session.RevokedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.SessionRevoked,
            currentUser.UserId, sessionId,
            currentUser.IpAddress, new { revokedSessionId = sessionId, targetUserId = session.UserId }, ct);

        return Result.Success();
    }

    public async Task<List<SessionDto>> GetUserSessionsAsync(Guid userId, Guid? currentSessionId, CancellationToken ct = default)
    {
        var sessions = await db.AuthenticationSessions
            .Where(s => s.UserId == userId && s.RevokedAtUtc == null && s.ExpiresAtUtc > DateTime.UtcNow)
            .OrderByDescending(s => s.LastSeenAtUtc)
            .ToListAsync(ct);

        return sessions.Select(s => new SessionDto(
            s.Id,
            s.IpAddress,
            s.UserAgent,
            s.CreatedAtUtc,
            s.LastSeenAtUtc,
            s.Id == currentSessionId)).ToList();
    }

    public async Task<User?> ValidateSessionAsync(string sessionToken, CancellationToken ct = default)
    {
        var session = await db.AuthenticationSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.SessionId == sessionToken
                                   && s.RevokedAtUtc == null
                                   && s.ExpiresAtUtc > DateTime.UtcNow, ct);

        if (session is null) return null;

        // Update last seen
        session.LastSeenAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        return session.User;
    }

    public async Task RevokeAllUserSessionsAsync(Guid userId, CancellationToken ct = default)
    {
        var sessions = await db.AuthenticationSessions
            .Where(s => s.UserId == userId && s.RevokedAtUtc == null)
            .ToListAsync(ct);

        foreach (var s in sessions)
            s.RevokedAtUtc = DateTime.UtcNow;

        await db.SaveChangesAsync(ct);
        logger.LogInformation("All sessions revoked for user {UserId}", userId);
    }
}
