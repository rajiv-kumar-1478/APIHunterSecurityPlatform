using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Common;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Auth;

public record LoginCommand(string Email, string Password, string IpAddress, string UserAgent);
public record LoginResult(Guid UserId, Guid SessionId, DateTime ExpiresAtUtc, bool IsPlatformAdmin);
public record ValidatedSession(Guid SessionId, Guid UserId, DateTime ExpiresAtUtc, bool IsPlatformAdmin);
public record SessionDto(Guid Id, string IpAddress, string UserAgent, DateTime CreatedAtUtc, DateTime LastSeenAtUtc, bool IsCurrent);

public class AuthService(
    IPlatformDbContext db,
    IPasswordHasher<User> passwordHasher,
    IAuditService auditService,
    ICurrentUserContext currentUser,
    IOptions<AuthenticationOptions> authOptions,
    ILogger<AuthService> logger)
{
    private static readonly TimeSpan LastSeenWriteInterval = TimeSpan.FromMinutes(5);
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

        var now = DateTime.UtcNow;

        if (user.LockoutUntilUtc.HasValue && user.LockoutUntilUtc.Value > now)
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
                user.LockoutUntilUtc = now.AddMinutes(_authOpts.LockoutDurationMinutes);
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

        user.FailedLoginCount = 0;
        user.LockoutUntilUtc = null;
        user.LastLoginAtUtc = now;

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = passwordHasher.HashPassword(user, command.Password);
        }

        // Make room for the new session by revoking the oldest active rows first.
        // This keeps the configured cap authoritative even when old cookies still exist.
        var maxConcurrentSessions = Math.Max(1, _authOpts.MaxConcurrentSessions);
        var activeSessions = await db.AuthenticationSessions
            .Where(s => s.UserId == user.Id && s.RevokedAtUtc == null && s.ExpiresAtUtc > now)
            .OrderBy(s => s.LastSeenAtUtc)
            .ThenBy(s => s.CreatedAtUtc)
            .ToListAsync(ct);

        var sessionsToRevoke = Math.Max(0, activeSessions.Count - maxConcurrentSessions + 1);
        foreach (var staleSession in activeSessions.Take(sessionsToRevoke))
        {
            staleSession.RevokedAtUtc = now;
        }

        var session = new AuthenticationSession
        {
            SessionId = Guid.NewGuid().ToString("N"),
            UserId = user.Id,
            ExpiresAtUtc = now.AddMinutes(_authOpts.SessionDurationMinutes),
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent,
            CreatedAtUtc = now,
            LastSeenAtUtc = now
        };

        db.AuthenticationSessions.Add(session);
        await db.SaveChangesAsync(ct);

        await auditService.RecordAsync(AuditEventCode.UserLogin, user.Id, session.Id,
            command.IpAddress, new { sessionId = session.Id }, ct);

        logger.LogInformation("User {UserId} logged in from {Ip}", user.Id, command.IpAddress);

        return Result<LoginResult>.Success(new LoginResult(
            user.Id,
            session.Id,
            session.ExpiresAtUtc,
            user.IsPlatformAdmin));
    }

    public async Task<Result> LogoutAsync(Guid sessionId, CancellationToken ct = default)
    {
        var session = await db.AuthenticationSessions.FindAsync([sessionId], ct);
        if (session is null) return Result.Success();

        session.RevokedAtUtc ??= DateTime.UtcNow;
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

        if (!currentUser.IsPlatformAdmin && session.UserId != currentUser.UserId)
            return Result.Failure("Access denied", "ACCESS_DENIED");

        session.RevokedAtUtc ??= DateTime.UtcNow;
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

    public async Task<ValidatedSession?> ValidateSessionAsync(Guid sessionId, CancellationToken ct = default)
    {
        var session = await db.AuthenticationSessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.Id == sessionId, ct);

        var now = DateTime.UtcNow;
        if (session is null ||
            session.RevokedAtUtc.HasValue ||
            session.ExpiresAtUtc <= now ||
            !session.User.IsActive)
        {
            return null;
        }

        if (now - session.LastSeenAtUtc >= LastSeenWriteInterval)
        {
            session.LastSeenAtUtc = now;
            await db.SaveChangesAsync(ct);
        }

        return new ValidatedSession(
            session.Id,
            session.UserId,
            session.ExpiresAtUtc,
            session.User.IsPlatformAdmin);
    }

    public async Task RevokeAllUserSessionsAsync(Guid userId, CancellationToken ct = default)
    {
        var sessions = await db.AuthenticationSessions
            .Where(s => s.UserId == userId && s.RevokedAtUtc == null)
            .ToListAsync(ct);

        var revokedAtUtc = DateTime.UtcNow;
        foreach (var session in sessions)
        {
            session.RevokedAtUtc = revokedAtUtc;
        }

        await db.SaveChangesAsync(ct);
        logger.LogInformation("All sessions revoked for user {UserId}", userId);
    }
}
