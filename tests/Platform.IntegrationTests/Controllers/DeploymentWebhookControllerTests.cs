using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Scanning.Verification;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class DeploymentWebhookControllerTests
{
    private readonly Mock<IDeploymentWebhookHandler> _mockHandler;
    private readonly DeploymentWebhookController _controller;

    public DeploymentWebhookControllerTests()
    {
        _mockHandler = new Mock<IDeploymentWebhookHandler>();
        _controller = new DeploymentWebhookController(
            _mockHandler.Object,
            NullLogger<DeploymentWebhookController>.Instance);
    }

    private void SetupRequest(string body, params (string Key, string Value)[] headers)
    {
        var httpContext = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(body);
        httpContext.Request.Body = new MemoryStream(bytes);
        httpContext.Request.ContentLength = bytes.Length;

        foreach (var (key, value) in headers)
        {
            httpContext.Request.Headers[key] = value;
        }

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }

    [Fact]
    public void Ping_Returns200Ok_WithOnlineStatus()
    {
        // Act
        var actionResult = _controller.Ping();

        // Assert
        var okResult = actionResult.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task HandleDeploymentWebhook_Success_Returns200Ok_WithScanJobId()
    {
        // Arrange
        var scanJobId = Guid.NewGuid();
        SetupRequest("{\"applicationId\":\"app-1\"}", ("X-Webhook-Id", "evt-1"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(true, scanJobId, "Deployment verification job successfully enqueued.", null));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var okResult = actionResult.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task HandleDeploymentWebhook_DuplicateEvent_Returns409Conflict()
    {
        // Arrange
        SetupRequest("{\"applicationId\":\"app-1\"}", ("X-Webhook-Id", "evt-dup"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(false, null, "Duplicate webhook event 'evt-dup' already processed.", "DUPLICATE_EVENT_ID"));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var conflictResult = actionResult.Should().BeOfType<ConflictObjectResult>().Subject;
        conflictResult.StatusCode.Should().Be(StatusCodes.Status409Conflict);
    }

    [Theory]
    [InlineData("UNAUTHORIZED_APPLICATION")]
    [InlineData("INVALID_SIGNATURE")]
    [InlineData("MISSING_SIGNATURE")]
    [InlineData("MISSING_SECRET_CONFIG")]
    public async Task HandleDeploymentWebhook_AuthErrors_Returns401Unauthorized(string errorCode)
    {
        // Arrange
        SetupRequest("{\"applicationId\":\"app-1\"}", ("X-Webhook-Id", "evt-1"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(false, null, "Authentication failure", errorCode));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var unauthorizedResult = actionResult.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorizedResult.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Theory]
    [InlineData("TIMESTAMP_OUT_OF_RANGE")]
    [InlineData("INVALID_TIMESTAMP")]
    [InlineData("MISSING_WEBHOOK_ID")]
    [InlineData("EMPTY_PAYLOAD")]
    [InlineData("MALFORMED_JSON")]
    [InlineData("MISSING_APPLICATION_ID")]
    public async Task HandleDeploymentWebhook_BadRequests_Returns400BadRequest(string errorCode)
    {
        // Arrange
        SetupRequest("{}", ("X-Webhook-Id", "evt-1"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(false, null, "Bad request failure", errorCode));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var badRequestResult = actionResult.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task HandleDeploymentWebhook_EnqueueFailed_Returns500InternalServerError()
    {
        // Arrange
        SetupRequest("{\"applicationId\":\"app-1\"}", ("X-Webhook-Id", "evt-1"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(false, null, "Scan job enqueue failed.", "SCAN_JOB_ENQUEUE_FAILED"));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var objectResult = actionResult.Should().BeOfType<ObjectResult>().Subject;
        objectResult.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
    }

    [Fact]
    public async Task HandleDeploymentWebhook_GenericError_Returns400BadRequest()
    {
        // Arrange
        SetupRequest("{\"applicationId\":\"app-1\"}", ("X-Webhook-Id", "evt-1"));

        _mockHandler
            .Setup(h => h.HandleWebhookAsync(It.IsAny<string>(), It.IsAny<IReadOnlyDictionary<string, string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DeploymentWebhookResponse(false, null, "Something went wrong.", "UNKNOWN_CUSTOM_ERROR"));

        // Act
        var actionResult = await _controller.HandleDeploymentWebhook(CancellationToken.None);

        // Assert
        var badRequestResult = actionResult.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
    }
}
