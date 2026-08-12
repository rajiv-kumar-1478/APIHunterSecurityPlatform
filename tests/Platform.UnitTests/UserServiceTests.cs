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
        // Arrange
        _passwordHasherMock
            .Setup(x => x.HashPassword(It.IsAny<User>(), "password123"))
            .Returns("hashed_pass");

        var command = new CreateUserCommand("newuser@test.com", "newuser", "New User", "password123", false);

        // Act
        var result = await _sut.CreateUserAsync(command);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();
        result.Value!.Email.Should().Be("newuser@test.com");

        var userInDb = await _db.Users.FirstOrDefaultAsync(u => u.Email == "newuser@test.com");
        userInDb.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateUserAsync_WithDuplicateEmail_ReturnsError()
    {
        // Arrange
        var existing = new User { Email = "existing@test.com", Username = "existing", DisplayName = "Existing User", PasswordHash = "hash" };
        _db.Users.Add(existing);
        await _db.SaveChangesAsync();

        var command = new CreateUserCommand("existing@test.com", "another", "Another User", "password123", false);

        // Act
        var result = await _sut.CreateUserAsync(command);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("already registered");
    }

    [Fact]
    public async Task GetUsersAsync_ReturnsPaginatedUsers()
    {
        // Arrange
        for (int i = 1; i <= 5; i++)
        {
            _db.Users.Add(new User { Email = $"user{i}@test.com", Username = $"user{i}", DisplayName = $"User {i}", PasswordHash = "hash" });
        }
        await _db.SaveChangesAsync();

        // Act
        var result = await _sut.GetUsersAsync(new PaginationRequest(1, 2));

        // Assert
        result.TotalCount.Should().Be(5);
        result.Items.Should().HaveCount(2);
        result.TotalPages.Should().Be(3);
    }
}
