using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Scanning.Verification;
using Platform.Domain.Contracts;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class RegisteredApplicationsControllerTests
{
    private readonly Mock<IRegisteredApplicationService> _mockService;
    private readonly Mock<ITenantContext> _mockTenantContext;
    private readonly RegisteredApplicationsController _controller;
    private readonly Guid _tenantId = Guid.NewGuid();

    public RegisteredApplicationsControllerTests()
    {
        _mockService = new Mock<IRegisteredApplicationService>();
        _mockTenantContext = new Mock<ITenantContext>();
        _mockTenantContext.Setup(t => t.TenantId).Returns(_tenantId);

        _controller = new RegisteredApplicationsController(
            _mockService.Object,
            _mockTenantContext.Object);
    }

    [Fact]
    public async Task GetApplications_Returns200Ok_WithList()
    {
        // Arrange
        var appList = new List<RegisteredApplicationDto>
        {
            new(Guid.NewGuid(), "app-1", "App 1", "https://api.test", "Prod", true, DateTime.UtcNow, DateTime.UtcNow)
        };
        _mockService
            .Setup(s => s.GetApplicationsAsync(_tenantId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(appList);

        // Act
        var result = await _controller.GetApplications(CancellationToken.None);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(StatusCodes.Status200OK);
        okResult.Value.Should().BeEquivalentTo(appList);
    }

    [Fact]
    public async Task RegisterApplication_ValidRequest_Returns201Created_WithRawSecret()
    {
        // Arrange
        var req = new RegisterApplicationRequest("app-ci", "CI Pipeline", "https://api.test", "Staging");
        var appDto = new RegisteredApplicationDto(Guid.NewGuid(), "app-ci", "CI Pipeline", "https://api.test", "Staging", true, DateTime.UtcNow, DateTime.UtcNow);
        var regResult = new RegistrationResultDto(appDto, "secret-hex-token");

        _mockService
            .Setup(s => s.RegisterApplicationAsync(_tenantId, req, It.IsAny<CancellationToken>()))
            .ReturnsAsync(regResult);

        // Act
        var result = await _controller.RegisterApplication(req, CancellationToken.None);

        // Assert
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        createdResult.StatusCode.Should().Be(StatusCodes.Status201Created);
        createdResult.Value.Should().BeEquivalentTo(regResult);
    }

    [Fact]
    public async Task RegisterApplication_Duplicate_Returns409Conflict()
    {
        // Arrange
        var req = new RegisterApplicationRequest("dup-app", "Dup", "https://api.test", "Prod");

        _mockService
            .Setup(s => s.RegisterApplicationAsync(_tenantId, req, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("An application with identifier already exists."));

        // Act
        var result = await _controller.RegisterApplication(req, CancellationToken.None);

        // Assert
        var conflictResult = result.Should().BeOfType<ConflictObjectResult>().Subject;
        conflictResult.StatusCode.Should().Be(StatusCodes.Status409Conflict);
    }

    [Fact]
    public async Task RegenerateSecret_ExistingApp_Returns200Ok_WithNewSecret()
    {
        // Arrange
        var appId = Guid.NewGuid();
        var rotationResult = new SecretRotationResultDto(appId, "app-ci", "new-secret-hex");

        _mockService
            .Setup(s => s.RegenerateSecretAsync(_tenantId, appId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(rotationResult);

        // Act
        var result = await _controller.RegenerateSecret(appId, CancellationToken.None);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(StatusCodes.Status200OK);
        okResult.Value.Should().BeEquivalentTo(rotationResult);
    }

    [Fact]
    public async Task ToggleStatus_ExistingApp_Returns200Ok()
    {
        // Arrange
        var appId = Guid.NewGuid();
        var appDto = new RegisteredApplicationDto(appId, "app-ci", "CI", "https://api.test", "Prod", false, DateTime.UtcNow, DateTime.UtcNow);

        _mockService
            .Setup(s => s.ToggleStatusAsync(_tenantId, appId, false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(appDto);

        // Act
        var result = await _controller.ToggleStatus(appId, new RegisteredApplicationsController.ToggleStatusRequest(false), CancellationToken.None);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task DeleteApplication_ExistingApp_Returns204NoContent()
    {
        // Arrange
        var appId = Guid.NewGuid();
        _mockService
            .Setup(s => s.DeleteApplicationAsync(_tenantId, appId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteApplication(appId, CancellationToken.None);

        // Assert
        var noContentResult = result.Should().BeOfType<NoContentResult>().Subject;
        noContentResult.StatusCode.Should().Be(StatusCodes.Status204NoContent);
    }
}
