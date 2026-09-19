using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Common;
using Platform.Application.Permissions;
using Platform.Application.Users;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests;

public class UserServiceTests
{
    private readonly PlatformDbContext _db;
    private readonly Mock<IPasswordHasher<User>> _passwordHasherMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ICurrentUserContext> _currentUserMock;
    private readonly UserService _sut;

    public UserServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _db = new PlatformDbContext(options);
        _passwordHasherMock = new Mock<IPasswordHasher<User>>();
        _auditServiceMock = new Mock<IAuditService>();
        _currentUserMock = new Mock<ICurrentUserContext>();

        _sut = new UserService(_db, _passwordHasherMock.Object, _auditServiceMock.Object, _currentUserMock.Object);
    }

    [Fact]
    public async Task CreateUserAsync_WithUniqueEmail_CreatesUser()
    {
        _passwordHasherMock
            .Setup(x => x.HashPassword(It.IsAny<User>(), "password123"))
            .Returns("hashed_pass");

        var command = new CreateUserCommand("newuser@test.com", "newuser", "New User", "password123", false);

        var result = await _sut.CreateUserAsync(command);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();
        result.Value!.Email.Should().Be("newuser@test.com");

        var userInDb = await _db.Users.FirstOrDefaultAsync(u => u.Email == "newuser@test.com");
        userInDb.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateUserAsync_WithDuplicateEmail_ReturnsError()
    {
        var existing = new User
        {
            Email = "existing@test.com",
            Username = "existing",
            DisplayName = "Existing User",
            PasswordHash = "hash"
        };
        _db.Users.Add(existing);
        await _db.SaveChangesAsync();

        var command = new CreateUserCommand("existing@test.com", "another", "Another User", "password123", false);

        var result = await _sut.CreateUserAsync(command);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("already registered");
    }

    [Fact]
    public async Task GetUsersAsync_ReturnsPaginatedUsers()
    {
        for (var i = 1; i <= 5; i++)
        {
            _db.Users.Add(new User
            {
                Email = $"user{i}@test.com",
                Username = $"user{i}",
                DisplayName = $"User {i}",
                PasswordHash = "hash"
            });
        }
        await _db.SaveChangesAsync();

        var result = await _sut.GetUsersAsync(new PaginationRequest(1, 2));

        result.TotalCount.Should().Be(5);
        result.Items.Should().HaveCount(2);
        result.TotalPages.Should().Be(3);
    }

    [Fact]
    public async Task UpdateUserAsync_WhenActiveUserIsDisabled_RevokesSessions()
    {
        var (user, session) = await SeedUserAndSessionAsync(isActive: true, isPlatformAdmin: false);

        var result = await _sut.UpdateUserAsync(
            new UpdateUserCommand(user.Id, null, IsActive: false, IsPlatformAdmin: null));

        result.IsSuccess.Should().BeTrue();
        (await _db.Users.FindAsync(user.Id))!.IsActive.Should().BeFalse();
        (await _db.AuthenticationSessions.FindAsync(session.Id))!.RevokedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task UpdateUserAsync_WhenPlatformAdminIsDemoted_RevokesSessions()
    {
        var (user, session) = await SeedUserAndSessionAsync(isActive: true, isPlatformAdmin: true);

        var result = await _sut.UpdateUserAsync(
            new UpdateUserCommand(user.Id, null, IsActive: null, IsPlatformAdmin: false));

        result.IsSuccess.Should().BeTrue();
        (await _db.Users.FindAsync(user.Id))!.IsPlatformAdmin.Should().BeFalse();
        (await _db.AuthenticationSessions.FindAsync(session.Id))!.RevokedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task UpdateUserAsync_WhenOnlyProfileChanges_DoesNotRevokeSessions()
    {
        var (user, session) = await SeedUserAndSessionAsync(isActive: true, isPlatformAdmin: true);

        var result = await _sut.UpdateUserAsync(
            new UpdateUserCommand(user.Id, "Updated Display Name", IsActive: null, IsPlatformAdmin: null));

        result.IsSuccess.Should().BeTrue();
        result.Value!.DisplayName.Should().Be("Updated Display Name");
        (await _db.AuthenticationSessions.FindAsync(session.Id))!.RevokedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task UpdateUserAsync_WhenValuesAreUnchanged_DoesNotRevokeSessions()
    {
        var (user, session) = await SeedUserAndSessionAsync(isActive: true, isPlatformAdmin: true);

        var result = await _sut.UpdateUserAsync(
            new UpdateUserCommand(user.Id, user.DisplayName, IsActive: true, IsPlatformAdmin: true));

        result.IsSuccess.Should().BeTrue();
        (await _db.AuthenticationSessions.FindAsync(session.Id))!.RevokedAtUtc.Should().BeNull();
        _auditServiceMock.Verify(
            audit => audit.RecordAsync(
                It.IsAny<Platform.Domain.Enums.AuditEventCode>(),
                It.IsAny<Guid?>(),
                It.IsAny<Guid?>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private async Task<(User User, AuthenticationSession Session)> SeedUserAndSessionAsync(
        bool isActive,
        bool isPlatformAdmin)
    {
        var user = new User
        {
            Email = $"user-{Guid.NewGuid():N}@test.com",
            Username = $"user-{Guid.NewGuid():N}",
            DisplayName = "Existing Display Name",
            PasswordHash = "hash",
            IsActive = isActive,
            IsPlatformAdmin = isPlatformAdmin
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var session = new AuthenticationSession
        {
            UserId = user.Id,
            SessionId = Guid.NewGuid().ToString("N"),
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent",
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            LastSeenAtUtc = DateTime.UtcNow.AddMinutes(-5),
            ExpiresAtUtc = DateTime.UtcNow.AddHours(1)
        };
        _db.AuthenticationSessions.Add(session);
        await _db.SaveChangesAsync();

        return (user, session);
    }
}
