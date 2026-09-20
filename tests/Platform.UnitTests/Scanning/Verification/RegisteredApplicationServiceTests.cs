using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning.Verification;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning.Verification;

public class RegisteredApplicationServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IDataProtectionProvider> _mockDataProtectionProvider;
    private readonly Mock<IDataProtector> _mockProtector;
    private readonly RegisteredApplicationService _service;
    private readonly Guid _tenantId = Guid.NewGuid();

    public RegisteredApplicationServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("RegAppServiceDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockProtector = new Mock<IDataProtector>();
        _mockProtector
            .Setup(p => p.Protect(It.IsAny<byte[]>()))
            .Returns<byte[]>(bytes => bytes);

        _mockDataProtectionProvider = new Mock<IDataProtectionProvider>();
        _mockDataProtectionProvider
            .Setup(p => p.CreateProtector(It.IsAny<string>()))
            .Returns(_mockProtector.Object);

        _service = new RegisteredApplicationService(
            _dbContext,
            _mockDataProtectionProvider.Object,
            NullLogger<RegisteredApplicationService>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task RegisterApplicationAsync_ValidRequest_CreatesApplicationAndReturnsRawSecret()
    {
        // Arrange
        var request = new RegisterApplicationRequest(
            "app-ci-prod",
            "Production CI/CD",
            "https://api.example.com",
            "Production");

        // Act
        var result = await _service.RegisterApplicationAsync(_tenantId, request, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.RawSigningSecret.Should().NotBeNullOrWhiteSpace();
        result.RawSigningSecret.Length.Should().Be(64); // 32 bytes hex

        result.Application.ApplicationId.Should().Be("app-ci-prod");
        result.Application.DisplayName.Should().Be("Production CI/CD");
        result.Application.AuthorizedTargetUrl.Should().Be("https://api.example.com");
        result.Application.Environment.Should().Be("Production");
        result.Application.Enabled.Should().BeTrue();

        // Verify in DB
        var persisted = await _dbContext.RegisteredApplications.FirstOrDefaultAsync(a => a.Id == result.Application.Id);
        persisted.Should().NotBeNull();
        persisted!.TenantId.Should().Be(_tenantId);
    }

    [Fact]
    public async Task RegisterApplicationAsync_DuplicateApplicationId_ThrowsInvalidOperationException()
    {
        // Arrange
        var request = new RegisterApplicationRequest(
            "duplicate-app",
            "App 1",
            "https://api.example.com",
            "Production");

        await _service.RegisterApplicationAsync(_tenantId, request, CancellationToken.None);

        // Act & Assert
        var duplicateAct = () => _service.RegisterApplicationAsync(_tenantId, request, CancellationToken.None);
        await duplicateAct.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already exists*");
    }

    [Fact]
    public async Task GetApplicationsAsync_EnforcesTenantIsolation()
    {
        // Arrange
        var otherTenantId = Guid.NewGuid();

        await _service.RegisterApplicationAsync(_tenantId, new RegisterApplicationRequest("app-1", "App 1", "https://app1.local", "Prod"), CancellationToken.None);
        await _service.RegisterApplicationAsync(otherTenantId, new RegisterApplicationRequest("app-2", "App 2", "https://app2.local", "Prod"), CancellationToken.None);

        // Act
        var tenantApps = await _service.GetApplicationsAsync(_tenantId, CancellationToken.None);

        // Assert
        tenantApps.Should().HaveCount(1);
        tenantApps[0].ApplicationId.Should().Be("app-1");
    }

    [Fact]
    public async Task RegenerateSecretAsync_UpdatesSecretAndReturnsNewRawValue()
    {
        // Arrange
        var registered = await _service.RegisterApplicationAsync(_tenantId, new RegisterApplicationRequest("rotate-app", "Rotate App", "https://rotate.local", "Prod"), CancellationToken.None);

        // Act
        var rotated = await _service.RegenerateSecretAsync(_tenantId, registered.Application.Id, CancellationToken.None);

        // Assert
        rotated.Should().NotBeNull();
        rotated.RawSigningSecret.Should().NotBeNullOrWhiteSpace();
        rotated.RawSigningSecret.Length.Should().Be(64);
        rotated.RawSigningSecret.Should().NotBe(registered.RawSigningSecret);
    }

    [Fact]
    public async Task ToggleStatusAsync_UpdatesEnabledState()
    {
        // Arrange
        var registered = await _service.RegisterApplicationAsync(_tenantId, new RegisterApplicationRequest("toggle-app", "Toggle App", "https://toggle.local", "Prod"), CancellationToken.None);

        // Act
        var disabled = await _service.ToggleStatusAsync(_tenantId, registered.Application.Id, false, CancellationToken.None);

        // Assert
        disabled.Enabled.Should().BeFalse();

        var reenabled = await _service.ToggleStatusAsync(_tenantId, registered.Application.Id, true, CancellationToken.None);
        reenabled.Enabled.Should().BeTrue();
    }

    [Fact]
    public async Task DeleteApplicationAsync_RemovesFromDatabase()
    {
        // Arrange
        var registered = await _service.RegisterApplicationAsync(_tenantId, new RegisterApplicationRequest("del-app", "Del App", "https://del.local", "Prod"), CancellationToken.None);

        // Act
        var deleted = await _service.DeleteApplicationAsync(_tenantId, registered.Application.Id, CancellationToken.None);

        // Assert
        deleted.Should().BeTrue();
        var exists = await _dbContext.RegisteredApplications.AnyAsync(a => a.Id == registered.Application.Id);
        exists.Should().BeFalse();
    }
}
