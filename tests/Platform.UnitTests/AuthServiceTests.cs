using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Auth;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests;

public class AuthServiceTests
{
    private readonly PlatformDbContext _db;
    private readonly Mock<IPasswordHasher<User>> _passwordHasherMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ICurrentUserContext> _currentUserMock;
    private readonly IOptions<AuthenticationOptions> _authOptions;
    private readonly Mock<ILogger<AuthService>> _loggerMock;
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _db = new PlatformDbContext(options);
        _passwordHasherMock = new Mock<IPasswordHasher<User>>();
        _auditServiceMock = new Mock<IAuditService>();
        _currentUserMock = new Mock<ICurrentUserContext>();
        _loggerMock = new Mock<ILogger<AuthService>>();

        _authOptions = Options.Create(new AuthenticationOptions
        {
            SessionDurationMinutes = 60,
            LockoutThreshold = 3,
            LockoutDurationMinutes = 15,
            MaxConcurrentSessions = 2
        });

        _sut = new AuthService(
            _db,
            _passwordHasherMock.Object,
            _auditServiceMock.Object,
            _currentUserMock.Object,
            _authOptions,
            _loggerMock.Object);
    }

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ReturnsRealUserAndSessionRowIds()
    {
        var user = new User
        {
            Email = "admin@test.com",
            Username = "admin",
            DisplayName = "Admin",
            PasswordHash = "hashed_pass",
            IsActive = true,
            IsPlatformAdmin = true
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "password123"))
            .Returns(PasswordVerificationResult.Success);

        var command = new LoginCommand("admin@test.com", "password123", "127.0.0.1", "TestAgent");

        var result = await _sut.LoginAsync(command);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();
        result.Value!.UserId.Should().Be(user.Id);

        var sessionInDb = await _db.AuthenticationSessions.SingleAsync();
        result.Value.SessionId.Should().Be(sessionInDb.Id);
        sessionInDb.UserId.Should().Be(user.Id);
        sessionInDb.IpAddress.Should().Be("127.0.0.1");
    }

    [Fact]
    public async Task LoginAsync_WithInvalidPassword_IncrementsFailedAttemptsAndFails()
    {
        var user = new User
        {
            Email = "user@test.com",
            Username = "user",
            DisplayName = "User",
            PasswordHash = "hashed_pass",
            IsActive = true,
            IsPlatformAdmin = false
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "wrongpass"))
            .Returns(PasswordVerificationResult.Failed);

        var command = new LoginCommand("user@test.com", "wrongpass", "127.0.0.1", "TestAgent");

        var result = await _sut.LoginAsync(command);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid");

        var updatedUser = await _db.Users.FindAsync(user.Id);
        updatedUser!.FailedLoginCount.Should().Be(1);
    }

    [Fact]
    public async Task LoginAsync_ExceedingLockoutThreshold_LocksAccount()
    {
        var user = new User
        {
            Email = "locked@test.com",
            Username = "locked",
            DisplayName = "Locked User",
            PasswordHash = "hashed_pass",
            IsActive = true,
            FailedLoginCount = 2
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "wrongpass"))
            .Returns(PasswordVerificationResult.Failed);

        var command = new LoginCommand("locked@test.com", "wrongpass", "127.0.0.1", "TestAgent");

        var result = await _sut.LoginAsync(command);

        result.IsSuccess.Should().BeFalse();

        var updatedUser = await _db.Users.FindAsync(user.Id);
        updatedUser!.LockoutUntilUtc.Should().NotBeNull();
        updatedUser.LockoutUntilUtc.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task LogoutAsync_WithValidSession_RevokesSession()
    {
        var session = new AuthenticationSession
        {
            UserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid().ToString("N"),
            IpAddress = "127.0.0.1",
            UserAgent = "Agent",
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(60)
        };
        _db.AuthenticationSessions.Add(session);
        await _db.SaveChangesAsync();

        await _sut.LogoutAsync(session.Id);

        var updatedSession = await _db.AuthenticationSessions.FindAsync(session.Id);
        updatedSession!.RevokedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task LoginAsync_WithUnknownEmail_FailsSafely()
    {
        var command = new LoginCommand("nonexistent@test.com", "anypass", "127.0.0.1", "TestAgent");

        var result = await _sut.LoginAsync(command);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid");
    }

    [Fact]
    public async Task LoginAsync_WithExpiredLockout_AllowsAttemptAndResetsLockout()
    {
        var user = new User
        {
            Email = "expiredlockout@test.com",
            Username = "expiredlock",
            DisplayName = "Expired Lock User",
            PasswordHash = "hashed_pass",
            IsActive = true,
            FailedLoginCount = 3,
            LockoutUntilUtc = DateTime.UtcNow.AddMinutes(-5)
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "password123"))
            .Returns(PasswordVerificationResult.Success);

        var command = new LoginCommand("expiredlockout@test.com", "password123", "127.0.0.1", "TestAgent");

        var result = await _sut.LoginAsync(command);

        result.IsSuccess.Should().BeTrue();
        var updatedUser = await _db.Users.FindAsync(user.Id);
        updatedUser!.FailedLoginCount.Should().Be(0);
        updatedUser.LockoutUntilUtc.Should().BeNull();
    }

    [Fact]
    public async Task ValidateSessionAsync_WithValidSession_ReturnsPersistedIdentity()
    {
        var user = await SeedUserAsync("valid-session@test.com", isActive: true, isPlatformAdmin: true);
        var session = await SeedSessionAsync(user, DateTime.UtcNow.AddMinutes(30));

        var validated = await _sut.ValidateSessionAsync(session.Id);

        validated.Should().NotBeNull();
        validated!.SessionId.Should().Be(session.Id);
        validated.UserId.Should().Be(user.Id);
        validated.IsPlatformAdmin.Should().BeTrue();
        validated.ExpiresAtUtc.Should().Be(session.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("disabled")]
    public async Task ValidateSessionAsync_WithInvalidSessionState_ReturnsNull(string invalidState)
    {
        var user = await SeedUserAsync(
            $"{invalidState}-session@test.com",
            isActive: invalidState != "disabled");
        var session = await SeedSessionAsync(
            user,
            invalidState == "expired" ? DateTime.UtcNow.AddMinutes(-1) : DateTime.UtcNow.AddMinutes(30),
            invalidState == "revoked" ? DateTime.UtcNow.AddMinutes(-1) : null);

        var validated = await _sut.ValidateSessionAsync(session.Id);

        validated.Should().BeNull();
    }

    [Fact]
    public async Task LoginAsync_AtConcurrentSessionCap_RevokesOldestActiveSession()
    {
        var user = await SeedUserAsync("session-cap@test.com", isActive: true);
        var oldest = await SeedSessionAsync(
            user,
            DateTime.UtcNow.AddMinutes(30),
            createdAtUtc: DateTime.UtcNow.AddHours(-2));
        var newer = await SeedSessionAsync(
            user,
            DateTime.UtcNow.AddMinutes(30),
            createdAtUtc: DateTime.UtcNow.AddHours(-1));

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "password123"))
            .Returns(PasswordVerificationResult.Success);

        var result = await _sut.LoginAsync(
            new LoginCommand(user.Email, "password123", "127.0.0.1", "CapTestAgent"));

        result.IsSuccess.Should().BeTrue();
        var sessions = await _db.AuthenticationSessions
            .Where(s => s.UserId == user.Id)
            .ToListAsync();
        sessions.Count(s => s.RevokedAtUtc == null && s.ExpiresAtUtc > DateTime.UtcNow)
            .Should().Be(2);
        sessions.Single(s => s.Id == oldest.Id).RevokedAtUtc.Should().NotBeNull();
        sessions.Single(s => s.Id == newer.Id).RevokedAtUtc.Should().BeNull();
        sessions.Single(s => s.Id == result.Value!.SessionId).RevokedAtUtc.Should().BeNull();
    }

    private async Task<User> SeedUserAsync(
        string email,
        bool isActive,
        bool isPlatformAdmin = false)
    {
        var user = new User
        {
            Email = email,
            Username = email.Split('@')[0],
            DisplayName = email,
            PasswordHash = "hashed_pass",
            IsActive = isActive,
            IsPlatformAdmin = isPlatformAdmin
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return user;
    }

    private async Task<AuthenticationSession> SeedSessionAsync(
        User user,
        DateTime expiresAtUtc,
        DateTime? revokedAtUtc = null,
        DateTime? createdAtUtc = null)
    {
        var created = createdAtUtc ?? DateTime.UtcNow;
        var session = new AuthenticationSession
        {
            UserId = user.Id,
            SessionId = Guid.NewGuid().ToString("N"),
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent",
            ExpiresAtUtc = expiresAtUtc,
            RevokedAtUtc = revokedAtUtc,
            CreatedAtUtc = created,
            LastSeenAtUtc = created
        };
        _db.AuthenticationSessions.Add(session);
        await _db.SaveChangesAsync();
        return session;
    }
}
