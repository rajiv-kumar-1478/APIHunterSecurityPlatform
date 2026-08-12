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
            LockoutDurationMinutes = 15
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
    public async Task LoginAsync_WithValidCredentials_ReturnsSuccessAndCreatesSession()
    {
        // Arrange
        var user = new User
        {
            Email = "admin@test.com",
            Username = "admin",
            DisplayName = "Admin",
            PasswordHash = "hashed_pass",
            IsPlatformAdmin = true
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "password123"))
            .Returns(PasswordVerificationResult.Success);

        var command = new LoginCommand("admin@test.com", "password123", "127.0.0.1", "TestAgent");

        // Act
        var result = await _sut.LoginAsync(command);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();

        var sessionInDb = await _db.AuthenticationSessions.FirstOrDefaultAsync(s => s.Id == result.Value!.SessionId);
        sessionInDb.Should().NotBeNull();
        sessionInDb!.IpAddress.Should().Be("127.0.0.1");
    }

    [Fact]
    public async Task LoginAsync_WithInvalidPassword_IncrementsFailedAttemptsAndFails()
    {
        // Arrange
        var user = new User
        {
            Email = "user@test.com",
            Username = "user",
            DisplayName = "User",
            PasswordHash = "hashed_pass",
            IsPlatformAdmin = false
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "wrongpass"))
            .Returns(PasswordVerificationResult.Failed);

        var command = new LoginCommand("user@test.com", "wrongpass", "127.0.0.1", "TestAgent");

        // Act
        var result = await _sut.LoginAsync(command);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Invalid");

        var updatedUser = await _db.Users.FindAsync(user.Id);
        updatedUser!.FailedLoginCount.Should().Be(1);
    }

    [Fact]
    public async Task LoginAsync_ExceedingLockoutThreshold_LocksAccount()
    {
        // Arrange
        var user = new User
        {
            Email = "locked@test.com",
            Username = "locked",
            DisplayName = "Locked User",
            PasswordHash = "hashed_pass",
            FailedLoginCount = 2
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _passwordHasherMock
            .Setup(x => x.VerifyHashedPassword(user, user.PasswordHash, "wrongpass"))
            .Returns(PasswordVerificationResult.Failed);

        var command = new LoginCommand("locked@test.com", "wrongpass", "127.0.0.1", "TestAgent");

        // Act
        var result = await _sut.LoginAsync(command);

        // Assert
        result.IsSuccess.Should().BeFalse();

        var updatedUser = await _db.Users.FindAsync(user.Id);
        updatedUser!.LockoutUntilUtc.Should().NotBeNull();
        updatedUser.LockoutUntilUtc.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task LogoutAsync_WithValidSession_RevokesSession()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var session = new AuthenticationSession
        {
            UserId = userId,
            SessionId = Guid.NewGuid().ToString("N"),
            IpAddress = "127.0.0.1",
            UserAgent = "Agent",
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(60)
        };
        _db.AuthenticationSessions.Add(session);
        await _db.SaveChangesAsync();

        // Act
        await _sut.LogoutAsync(session.Id);

        // Assert
        var updatedSession = await _db.AuthenticationSessions.FindAsync(session.Id);
        updatedSession!.RevokedAtUtc.Should().NotBeNull();
    }
}
