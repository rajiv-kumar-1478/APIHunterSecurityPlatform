using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Permissions;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests;

public class AuditServiceTests
{
    private readonly PlatformDbContext _db;
    private readonly Mock<ICurrentUserContextProvider> _correlationProviderMock;
    private readonly Mock<ILogger<AuditService>> _loggerMock;
    private readonly AuditService _sut;

    public AuditServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _db = new PlatformDbContext(options);
        _correlationProviderMock = new Mock<ICurrentUserContextProvider>();
        _loggerMock = new Mock<ILogger<AuditService>>();

        _correlationProviderMock.Setup(c => c.CorrelationId).Returns("test_correlation_123");

        _sut = new AuditService(_db, _correlationProviderMock.Object, _loggerMock.Object);
    }

    [Fact]
    public async Task RecordAsync_CreatesAuditEventWithCorrelationIdAndIp()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        // Act
        await _sut.RecordAsync(AuditEventCode.UserLogin, userId, sessionId, "192.168.1.100", new { username = "testuser" });

        // Assert
        var eventInDb = await _db.AuditEvents.FirstOrDefaultAsync(a => a.UserId == userId);
        eventInDb.Should().NotBeNull();
        eventInDb!.EventCode.Should().Be(AuditEventCode.UserLogin);
        eventInDb.CorrelationId.Should().Be("test_correlation_123");
        eventInDb.IpAddress.Should().Be("192.168.1.100");
        eventInDb.Metadata.Should().Contain("testuser");
    }
}
