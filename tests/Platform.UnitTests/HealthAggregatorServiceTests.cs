using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Health;
using Platform.Domain.Contracts;
using Platform.Domain.ValueObjects;
using Xunit;

namespace Platform.UnitTests;

public class HealthAggregatorServiceTests
{
    private readonly Mock<ILogger<HealthAggregatorService>> _loggerMock = new();

    [Fact]
    public async Task CheckAllAsync_WhenAllComponentsHealthy_ReturnsOverallHealthy()
    {
        // Arrange
        var comp1 = new Mock<IHealthComponent>();
        comp1.Setup(c => c.ComponentName).Returns("PostgreSQL");
        comp1.Setup(c => c.CheckAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ComponentHealthResult("PostgreSQL", true, "Healthy", null, TimeSpan.FromMilliseconds(5)));

        var comp2 = new Mock<IHealthComponent>();
        comp2.Setup(c => c.ComponentName).Returns("API");
        comp2.Setup(c => c.CheckAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ComponentHealthResult("API", true, "Healthy", "v1.0.0", TimeSpan.Zero));

        var sut = new HealthAggregatorService(new[] { comp1.Object, comp2.Object }, _loggerMock.Object);

        // Act
        var result = await sut.CheckAllAsync();

        // Assert
        result.IsHealthy.Should().BeTrue();
        result.OverallStatus.Should().Be("Healthy");
        result.Components.Should().HaveCount(2);
    }

    [Fact]
    public async Task CheckAllAsync_WhenOneComponentUnhealthy_ReturnsOverallUnhealthy()
    {
        // Arrange
        var comp1 = new Mock<IHealthComponent>();
        comp1.Setup(c => c.ComponentName).Returns("PostgreSQL");
        comp1.Setup(c => c.CheckAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ComponentHealthResult("PostgreSQL", false, "Unhealthy", "Connection refused", TimeSpan.FromMilliseconds(100)));

        var comp2 = new Mock<IHealthComponent>();
        comp2.Setup(c => c.ComponentName).Returns("API");
        comp2.Setup(c => c.CheckAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ComponentHealthResult("API", true, "Healthy", "v1.0.0", TimeSpan.Zero));

        var sut = new HealthAggregatorService(new[] { comp1.Object, comp2.Object }, _loggerMock.Object);

        // Act
        var result = await sut.CheckAllAsync();

        // Assert
        result.IsHealthy.Should().BeFalse();
        result.OverallStatus.Should().Be("Degraded");
        result.Components.Should().HaveCount(2);
    }
}
