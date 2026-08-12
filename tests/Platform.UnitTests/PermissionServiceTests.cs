using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Permissions;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests;

public class PermissionServiceTests
{
    private readonly PlatformDbContext _db;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<ICurrentUserContext> _currentUserMock;
    private readonly PermissionService _sut;

    public PermissionServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _db = new PlatformDbContext(options);
        _auditServiceMock = new Mock<IAuditService>();
        _currentUserMock = new Mock<ICurrentUserContext>();
        _sut = new PermissionService(_db, _auditServiceMock.Object, _currentUserMock.Object);
    }

    [Fact]
    public async Task GetCallerPermissionsAsync_ReturnsGrantedPermissions()
    {
        // Arrange
        var user = new User { Email = "user@test.com", Username = "user", DisplayName = "User", PasswordHash = "hash" };
        var perm1 = new Permission { Code = "repo.read", Name = "Read Repositories", Category = "Catalog", Description = "Read access to repos" };
        var perm2 = new Permission { Code = "repo.write", Name = "Write Repositories", Category = "Catalog", Description = "Write access to repos" };

        _db.Users.Add(user);
        _db.Permissions.AddRange(perm1, perm2);
        _db.UserPermissions.Add(new UserPermission { UserId = user.Id, PermissionId = perm1.Id, Enabled = true });
        await _db.SaveChangesAsync();

        // Act
        var result = await _sut.GetCallerPermissionsAsync(user.Id);

        // Assert
        result.Should().ContainSingle();
        result.Select(p => p.Code).Should().Contain("repo.read");
        result.Select(p => p.Code).Should().NotContain("repo.write");
    }

    [Fact]
    public async Task SetUserPermissionsAsync_UpdatesUserPermissionsAtomically()
    {
        // Arrange
        var user = new User { Email = "user2@test.com", Username = "user2", DisplayName = "User 2", PasswordHash = "hash" };
        var perm1 = new Permission { Code = "audit.read", Name = "Read Audit", Category = "Audit", Description = "Read audit logs" };
        var perm2 = new Permission { Code = "user.read", Name = "Read Users", Category = "User", Description = "Read users" };

        _db.Users.Add(user);
        _db.Permissions.AddRange(perm1, perm2);
        _db.UserPermissions.Add(new UserPermission { UserId = user.Id, PermissionId = perm1.Id, Enabled = true });
        await _db.SaveChangesAsync();

        var command = new GrantPermissionsCommand(user.Id, new List<string> { "user.read" });

        // Act
        var result = await _sut.SetUserPermissionsAsync(command);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var userPerms = await _db.UserPermissions
            .Include(up => up.Permission)
            .Where(p => p.UserId == user.Id && p.Enabled)
            .Select(p => p.Permission.Code)
            .ToListAsync();

        userPerms.Should().ContainSingle();
        userPerms.Should().Contain("user.read");
        userPerms.Should().NotContain("audit.read");
    }

    [Fact]
    public async Task UpsertFieldPermissionAsync_CreatesAndUpdatesFieldPermissions()
    {
        // Arrange
        var command = new UpsertFieldPermissionCommand("repo.read", "Repository", "SecretKey", FieldAction.Read, PermissionEffect.Deny);

        // Act
        var result = await _sut.UpsertFieldPermissionAsync(command);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var fieldPerm = await _db.FieldPermissions.FirstOrDefaultAsync(fp => fp.PermissionCode == "repo.read" && fp.FieldName == "SecretKey");
        fieldPerm.Should().NotBeNull();
        fieldPerm!.Effect.Should().Be(PermissionEffect.Deny);
    }
}
