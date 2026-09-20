using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Operations;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Operations;

public class AiOperationalDiagnosisTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAiModelRouter> _mockRouter;
    private readonly OperationalPromptSanitizer _sanitizer;
    private readonly AiOperationalDiagnosisService _service;
    private readonly Guid _tenantId = Guid.NewGuid();

    public AiOperationalDiagnosisTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiDiagnosisDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockRouter = new Mock<IAiModelRouter>();
        _sanitizer = new OperationalPromptSanitizer();

        _service = new AiOperationalDiagnosisService(
            _dbContext,
            _mockRouter.Object,
            _sanitizer,
            NullLogger<AiOperationalDiagnosisService>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task DiagnoseIncidentAsync_ValidAiResponse_ParsesJsonAndStoresDiagnosis()
    {
        var incident = new OperationalIncident
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            Title = "Scan Worker OOM Crash",
            Category = IncidentCategory.WorkerHeartbeatLost,
            Severity = IncidentSeverity.High,
            Fingerprint = "oom_crash_worker_1"
        };
        _dbContext.OperationalIncidents.Add(incident);
        await _dbContext.SaveChangesAsync();

        var aiJsonResponse =
            """
            {
              "rootCause": "Worker container exceeded 2GB memory quota while parsing 100MB JS bundle.",
              "remediation": "Increase worker container memory limit to 4GB and enable streaming AST parser.",
              "confidence": 0.94
            }
            """;

        var mockResponse = new AiPromptResponse(
            IsSuccess: true,
            RawResponseContent: aiJsonResponse,
            NormalizedJsonContent: aiJsonResponse,
            PromptTokens: 250,
            CompletionTokens: 60,
            ProviderName: "openai",
            ModelName: "gpt-4o",
            LatencyMs: 400,
            ErrorCode: null,
            ErrorMessage: null,
            IsRetryable: false);

        _mockRouter
            .Setup(r => r.ExecuteWithFallbackAsync(It.IsAny<AiPromptRequest>(), It.IsAny<IEnumerable<string>?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((mockResponse, "openai", "gpt-4o"));

        // Act
        var diagnosis = await _service.DiagnoseIncidentAsync(incident.Id);

        // Assert
        diagnosis.Should().NotBeNull();
        diagnosis.RootCauseSummary.Should().Contain("memory quota");
        diagnosis.SuggestedRemediation.Should().Contain("streaming AST parser");
        diagnosis.ConfidenceScore.Should().Be(0.94);
        diagnosis.IsDeterministicFallback.Should().BeFalse();
        diagnosis.ProviderUsed.Should().Be("openai");

        var refreshedIncident = await _dbContext.OperationalIncidents.FindAsync(incident.Id);
        refreshedIncident!.AiDiagnosisId.Should().Be(diagnosis.Id);
        refreshedIncident.Status.Should().Be(IncidentStatus.Investigating);
    }

    [Fact]
    public async Task DiagnoseIncidentAsync_AiRouterFails_UsesDeterministicFallback()
    {
        var incident = new OperationalIncident
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            Title = "Scheduler Missed Window",
            Category = IncidentCategory.CampaignStall,
            Severity = IncidentSeverity.Medium,
            Fingerprint = "campaign_stall_10"
        };
        _dbContext.OperationalIncidents.Add(incident);
        await _dbContext.SaveChangesAsync();

        var failureResponse = new AiPromptResponse(
            IsSuccess: false,
            RawResponseContent: string.Empty,
            NormalizedJsonContent: null,
            PromptTokens: 0,
            CompletionTokens: 0,
            ProviderName: "System",
            ModelName: "None",
            LatencyMs: 50,
            ErrorCode: "RateLimitExceeded",
            ErrorMessage: "AI providers temporarily exhausted",
            IsRetryable: true);

        _mockRouter
            .Setup(r => r.ExecuteWithFallbackAsync(It.IsAny<AiPromptRequest>(), It.IsAny<IEnumerable<string>?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((failureResponse, "System", "None"));

        // Act
        var diagnosis = await _service.DiagnoseIncidentAsync(incident.Id);

        // Assert
        diagnosis.Should().NotBeNull();
        diagnosis.IsDeterministicFallback.Should().BeTrue();
        diagnosis.ProviderUsed.Should().Be("DeterministicFallbackEngine");
        diagnosis.RootCauseSummary.Should().Contain("Continuous scan campaign missed its scheduled execution window");
        diagnosis.ConfidenceScore.Should().BeGreaterThanOrEqualTo(0.85);
    }
}
