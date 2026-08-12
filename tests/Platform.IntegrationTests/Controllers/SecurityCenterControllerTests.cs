using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class SecurityCenterControllerTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly Mock<PermissionService> _mockPermissionService;
    private readonly SecurityAlertOptions _alertOptions;
    private readonly SecurityCenterController _controller;

    public SecurityCenterControllerTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("SecurityCenterDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(true);
        _mockUser.Setup(u => u.UserId).Returns(Guid.NewGuid());

        var mockAuditService = new Mock<IAuditService>();
        _mockPermissionService = new Mock<PermissionService>(
            _dbContext, mockAuditService.Object, _mockUser.Object);

        _alertOptions = new SecurityAlertOptions
        {
            GlobalEnabled = true,
            CooldownMinutes = 60,
            HighSeverityThreshold = 60,
            CriticalSeverityThreshold = 80,
            RiskJumpThreshold = 25,
            AlertRecipientEmail = "secret-recipient@security.local"
        };

        _controller = new SecurityCenterController(
            _dbContext,
            Options.Create(_alertOptions),
            _mockUser.Object,
            _mockPermissionService.Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    // ─── T1: Posture reads persisted RepositoryRiskScore DB rows ──────────────

    [Fact]
    public async Task T1_GetSecurityPosture_Returns_Persisted_RiskScore_DB_Rows()
    {
        var repo = new Repository { FullName = "octocat/posture-repo" };
        _dbContext.Repositories.Add(repo);

        // Seed a persisted RepositoryRiskScore (simulating Step 2 RiskEngine output)
        _dbContext.RepositoryRiskScores.Add(new RepositoryRiskScore
        {
            RepositoryId = repo.Id,
            Score = 88,
            Severity = RiskSeverity.Critical,
            AlgorithmVersion = "v1.0",
            FactorBreakdownJson = "[{\"code\":\"BASE\",\"description\":\"Base Floor\",\"weight\":40}]",
            CalculatedAtUtc = DateTime.UtcNow
        });

        // Seed an open finding
        _dbContext.SecurityFindings.Add(new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            Title = "Critical Finding",
            Description = "Test finding",
            Status = FindingStatus.Open,
            RiskScore = 88
        });

        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetSecurityPosture();
        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<SecurityPostureDto>(okResult.Value);

        Assert.Equal(1, dto.TotalRepositoriesMonitored);
        Assert.Equal(88, dto.HighestRepositoryRiskScore);
        Assert.Equal("Critical", dto.OverallSeverity);
        Assert.Equal(1, dto.OpenFindingsCount);
        Assert.Equal(1, dto.CriticalFindingsCount);
    }

    // ─── T2: Alerting status returns sanitized DTO without secrets ────────────

    [Fact]
    public async Task T2_GetAlertingStatus_Returns_Sanitized_Dto_Without_Secrets()
    {
        var result = await _controller.GetAlertingStatus();
        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<AlertingStatusDto>(okResult.Value);

        Assert.True(dto.Enabled);
        Assert.Equal(60, dto.CooldownMinutes);
        Assert.Equal(60, dto.HighSeverityThreshold);
        Assert.Equal(80, dto.CriticalSeverityThreshold);
        Assert.Equal(25, dto.RiskJumpThreshold);

        // Verify recipient email / SMTP secrets are NOT exposed on DTO
        var json = System.Text.Json.JsonSerializer.Serialize(dto);
        Assert.DoesNotContain("secret-recipient@security.local", json);
    }

    // ─── T3: Non-Admin without permission receives Forbid ──────────────────────

    [Fact]
    public async Task T3_NonAdmin_Without_Permission_Receives_Forbid()
    {
        var nonAdminUser = new Mock<ICurrentUserContext>();
        nonAdminUser.Setup(u => u.IsPlatformAdmin).Returns(false);
        nonAdminUser.Setup(u => u.UserId).Returns(Guid.NewGuid());

        _mockPermissionService
            .Setup(p => p.HasPermissionAsync(It.IsAny<Guid>(), "finding.view", It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var controller = new SecurityCenterController(
            _dbContext,
            Options.Create(_alertOptions),
            nonAdminUser.Object,
            _mockPermissionService.Object);

        var postureResult = await controller.GetSecurityPosture();
        Assert.IsType<ForbidResult>(postureResult);

        var alertResult = await controller.GetAlertingStatus();
        Assert.IsType<ForbidResult>(alertResult);
    }
}
