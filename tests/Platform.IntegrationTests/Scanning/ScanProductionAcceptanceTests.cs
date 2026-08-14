using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Reporting.Formatters;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.IntegrationTests.Scanning;

/// <summary>
/// Phase 8 Step 4.8: End-to-End Production Acceptance Pass.
/// Verifies the complete integrated chain: Target & Job Creation -> Multi-Tool Orchestration ->
/// Finding Ingestion & Risk Scoring -> Post-Execution Lifecycle -> Scan Diff -> Canonical Report Builder ->
/// 4 Formats (JSON, OASIS SARIF 2.1.0, Markdown, HTML) -> Tenant Authorization & Resource Limits.
/// </summary>
public class ScanProductionAcceptanceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly ScanJobService _scanJobService;
    private readonly ScanToolHealthService _toolHealthService;
    private readonly InMemoryScanProviderSecretStore _secretStore;
    private readonly ScanFindingIngestionEngine _ingestionEngine;
    private readonly ScanPostExecutionProcessor _postProcessor;
    private readonly ScanReportBuilderService _reportBuilder;
    private readonly SecurityReportFormatterRegistry _formatterRegistry;
    private readonly SecurityScanController _controller;

    private readonly Guid _tenantAId = Guid.NewGuid();
    private readonly Guid _tenantBId = Guid.NewGuid();
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanProductionAcceptanceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanProductionAcceptanceTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.UserId).Returns(_tenantAId);
        _mockUser.Setup(u => u.IsAuthenticated).Returns(true);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        _toolRegistryService = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _scanJobService = new ScanJobService(_dbContext, _mockUser.Object, _toolRegistryService, NullLogger<ScanJobService>.Instance);
        _toolHealthService = new ScanToolHealthService(_toolRegistryService, NullLogger<ScanToolHealthService>.Instance);
        _secretStore = new InMemoryScanProviderSecretStore();
        _ingestionEngine = new ScanFindingIngestionEngine(_dbContext, NullLogger<ScanFindingIngestionEngine>.Instance);
        _postProcessor = new ScanPostExecutionProcessor(_dbContext, _scanJobService, NullLogger<ScanPostExecutionProcessor>.Instance);
        _reportBuilder = new ScanReportBuilderService(_dbContext, _scanJobService, _postProcessor, NullLogger<ScanReportBuilderService>.Instance);
        _formatterRegistry = new SecurityReportFormatterRegistry();

        _controller = new SecurityScanController(
            _scanJobService,
            _toolRegistryService,
            _toolHealthService,
            _secretStore,
            _postProcessor,
            _reportBuilder);

        // Seed Repository and SecurityTarget
        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "ProductionApiGateway",
            FullName = "enterprise/ProductionApiGateway",
            Owner = "enterprise",
            Url = "https://github.com/enterprise/ProductionApiGateway",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Customer API Gateway",
            TargetType = "WebEndpoint",
            BaseUrl = "https://api.enterprise.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    [Fact]
    public async Task EndToEnd_ScanPipeline_FullProductionAcceptancePass()
    {
        // -------------------------------------------------------------
        // STEP 1: Launch Scan Job 1 (Standard Profile) for Tenant A
        // -------------------------------------------------------------
        var createRequest = new CreateScanJobRequest(
            RepositoryId: _repoId,
            TargetId: _targetId,
            TargetUrl: "https://api.enterprise.com",
            ScanProfile: SecurityScanProfileType.Standard
        );

        var createResult = await _controller.CreateJob(createRequest, default);
        var createdAction = createResult.Result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var createdJob = createdAction.Value.Should().BeOfType<SecurityScanJob>().Subject;
        createdJob.Status.Should().Be(SecurityScanJobStatus.Queued);
        createdJob.RequestedByUserId.Should().Be(_tenantAId);

        // -------------------------------------------------------------
        // STEP 2: Ingest Findings for Job 1 (Critical Auth Bypass + High Info Leak)
        // -------------------------------------------------------------
        var job1Start = DateTime.UtcNow.AddMinutes(-30);
        var job1End = DateTime.UtcNow.AddMinutes(-25);
        var job1Context = new ScanJobContext(createdJob.Id, _repoId, _targetId, "https://api.enterprise.com", SecurityScanProfileType.Standard, job1Start);
        var candidate1 = new FindingCandidate(
            ToolKey: "nuclei",
            ToolVersion: "v3.1.0",
            FindingType: FindingType.ValidatedCredentialExposed,
            Title: "Exposed Stripe Production Key in /v1/checkout",
            Description: "Live secret API key leaked in response body",
            RawSeverity: "critical",
            TargetUrl: "https://api.enterprise.com/v1/checkout",
            TemplateId: "stripe-key-leak",
            ExtractedData: "{\"secret\":\"sk-live-51ABC987654321\"}",
            CveId: "CVE-2024-9999",
            CweId: "CWE-798",
            ObservedAtUtc: job1Start
        );

        var candidate2 = new FindingCandidate(
            ToolKey: "katana",
            ToolVersion: "v1.1.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: "Unprotected Swagger UI in Production",
            Description: "Interactive OpenAPI documentation publicly exposed",
            RawSeverity: "high",
            TargetUrl: "https://api.enterprise.com/swagger/index.html",
            TemplateId: "swagger-exposed",
            ObservedAtUtc: job1Start
        );

        var ingestionResult = await _ingestionEngine.IngestCandidatesAsync(new[] { candidate1, candidate2 }, job1Context);
        ingestionResult.CandidatesAccepted.Should().Be(2);

        // Mark Job 1 Completed
        createdJob.Status = SecurityScanJobStatus.Completed;
        createdJob.StartedAtUtc = job1Start;
        createdJob.CompletedAtUtc = job1End;
        createdJob.CreatedAtUtc = job1Start;
        var receipt1 = new ScanExecutionReceipt(
            JobId: createdJob.Id,
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: job1Start,
            CompletedAtUtc: job1End,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.1.0", "nuclei", "ghcr.io/nuclei", "sha256:abc1", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, job1Start, job1End, 30000, 1024, 1, 0, 0, null, ToolFailureClassification.None),
                new ToolExecutionReceipt("katana", "v1.1.0", "katana", "ghcr.io/katana", "sha256:abc2", SecurityScanProfileType.Standard, ScanExecutionPhase.Discovery, ToolExecutionStatus.Success, job1Start, job1End, 20000, 512, 1, 0, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 2,
            TotalFindingsUpdated: 0,
            Summary: "Scan 1 completed with 2 findings."
        );
        createdJob.ExecutionReceiptJson = JsonSerializer.Serialize(receipt1);
        await _dbContext.SaveChangesAsync();

        // -------------------------------------------------------------
        // STEP 3: Post-Execution Processing for Job 1
        // -------------------------------------------------------------
        await _postProcessor.ProcessPostScanLifecycleAsync(createdJob.Id, default);

        var summaryRes = await _controller.GetJobSummary(createdJob.Id, default);
        var summaryOk = summaryRes.Result.Should().BeOfType<OkObjectResult>().Subject;
        var summary = summaryOk.Value.Should().BeOfType<ScanResultSummary>().Subject;
        summary.FindingsTotal.Should().Be(2);
        (summary.CriticalCount + summary.HighCount + summary.MediumCount).Should().Be(2);

        // -------------------------------------------------------------
        // STEP 4: Canonical Report Generation Across All 4 Formats
        // -------------------------------------------------------------
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(createdJob.Id);
        canonicalReport.Findings.Should().HaveCount(2);
        canonicalReport.Metadata.ProvenanceSignature.Should().NotBeNullOrWhiteSpace();

        // 1. JSON Report
        var jsonRes = await _controller.GetJsonReport(createdJob.Id, null, default);
        var jsonContent = jsonRes.Should().BeOfType<ContentResult>().Subject;
        jsonContent.ContentType.Should().StartWith("application/json");
        jsonContent.Content.Should().Contain("Exposed Stripe Production Key");
        jsonContent.Content.Should().NotContain("sk-live-51ABC987654321"); // Secret redacted

        // 2. SARIF 2.1.0 Report
        var sarifRes = await _controller.GetSarifReport(createdJob.Id, null, default);
        var sarifContent = sarifRes.Should().BeOfType<ContentResult>().Subject;
        sarifContent.ContentType.Should().StartWith("application/sarif+json");
        sarifContent.Content.Should().Contain("\"version\": \"2.1.0\"");

        // Validate SARIF against official schema fixture
        using (var sarifDoc = JsonDocument.Parse(sarifContent.Content))
        {
            var schemaPath = GetOfficialSarifSchemaPath();
            var schema = Json.Schema.JsonSchema.FromText(await File.ReadAllTextAsync(schemaPath));
            var evaluation = schema.Evaluate(sarifDoc.RootElement);
            evaluation.IsValid.Should().BeTrue("Generated SARIF must satisfy official OASIS SARIF 2.1.0 specification");
        }

        // 3. Markdown Report
        var mdRes = await _controller.GetMarkdownReport(createdJob.Id, null, default);
        var mdContent = mdRes.Should().BeOfType<ContentResult>().Subject;
        mdContent.ContentType.Should().StartWith("text/markdown");
        mdContent.Content.Should().Contain("# Security Assessment Report");
        mdContent.Content.Should().Contain("### 3.1");

        // 4. HTML Report
        var htmlRes = await _controller.GetHtmlReport(createdJob.Id, null, default);
        var htmlContent = htmlRes.Should().BeOfType<ContentResult>().Subject;
        htmlContent.ContentType.Should().StartWith("text/html");
        htmlContent.Content.Should().Contain("<!DOCTYPE html>");
        htmlContent.Content.Should().Contain("enterprise/ProductionApiGateway");

        // -------------------------------------------------------------
        // STEP 5: Scan Job 2 (Finding 1 resolved/absent) -> NotObserved (Count: 1)
        // -------------------------------------------------------------
        var job2Start = DateTime.UtcNow.AddMinutes(-20);
        var job2End = DateTime.UtcNow.AddMinutes(-15);
        var job2 = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.enterprise.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _tenantAId,
            StartedAtUtc = job2Start,
            CompletedAtUtc = job2End,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt1 with { JobId = Guid.NewGuid(), StartedAtUtc = job2Start, CompletedAtUtc = job2End }),
            CreatedAtUtc = job2Start
        };
        _dbContext.SecurityScanJobs.Add(job2);
        await _dbContext.SaveChangesAsync();

        // Ingest only candidate 2 (candidate 1 absent)
        var job2Context = new ScanJobContext(job2.Id, _repoId, _targetId, "https://api.enterprise.com", SecurityScanProfileType.Standard, job2Start);
        await _ingestionEngine.IngestCandidatesAsync(new[] { candidate2 with { ObservedAtUtc = job2Start } }, job2Context);
        await _postProcessor.ProcessPostScanLifecycleAsync(job2.Id, default);

        var diff2Res = await _controller.GetJobDiff(job2.Id, createdJob.Id, default);
        var diff2Ok = diff2Res.Result.Should().BeOfType<OkObjectResult>().Subject;
        var diff2 = diff2Ok.Value.Should().BeOfType<ScanDiff>().Subject;
        diff2.NotObservedFindings.Should().HaveCount(1);
        diff2.ResolvedFindings.Should().BeEmpty("Requires 2 consecutive absent scans for auto-resolution");

        // -------------------------------------------------------------
        // STEP 6: Scan Job 3 (Finding 1 absent 2nd time) -> Resolved
        // -------------------------------------------------------------
        var job3Start = DateTime.UtcNow.AddMinutes(-10);
        var job3End = DateTime.UtcNow.AddMinutes(-5);
        var job3 = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.enterprise.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _tenantAId,
            StartedAtUtc = job3Start,
            CompletedAtUtc = job3End,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt1 with { JobId = Guid.NewGuid(), StartedAtUtc = job3Start, CompletedAtUtc = job3End }),
            CreatedAtUtc = job3Start
        };
        _dbContext.SecurityScanJobs.Add(job3);
        await _dbContext.SaveChangesAsync();

        var job3Context = new ScanJobContext(job3.Id, _repoId, _targetId, "https://api.enterprise.com", SecurityScanProfileType.Standard, job3Start);
        await _ingestionEngine.IngestCandidatesAsync(new[] { candidate2 with { ObservedAtUtc = job3Start } }, job3Context);
        await _postProcessor.ProcessPostScanLifecycleAsync(job3.Id, default);

        var diff3Res = await _controller.GetJobDiff(job3.Id, createdJob.Id, default);
        var diff3Ok = diff3Res.Result.Should().BeOfType<OkObjectResult>().Subject;
        var diff3 = diff3Ok.Value.Should().BeOfType<ScanDiff>().Subject;
        diff3.ResolvedFindings.Should().HaveCount(1, "2 consecutive full-coverage absence scans confirmed resolution");

        // -------------------------------------------------------------
        // STEP 7: Tenant Isolation Verification (Tenant B Blocked - HTTP 403)
        // -------------------------------------------------------------
        _mockUser.Setup(u => u.UserId).Returns(_tenantBId);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        var bGetJob = await _controller.GetJob(createdJob.Id, default);
        bGetJob.Result.Should().BeOfType<ObjectResult>().Subject.StatusCode.Should().Be(403);

        var bGetSummary = await _controller.GetJobSummary(createdJob.Id, default);
        bGetSummary.Result.Should().BeOfType<ObjectResult>().Subject.StatusCode.Should().Be(403);

        var bGetDiff = await _controller.GetJobDiff(createdJob.Id, null, default);
        bGetDiff.Result.Should().BeOfType<ObjectResult>().Subject.StatusCode.Should().Be(403);

        var bGetReport = await _controller.GetReport(createdJob.Id, "json", null, default);
        bGetReport.Should().BeOfType<ObjectResult>().Subject.StatusCode.Should().Be(403);
    }

    private static string GetOfficialSarifSchemaPath()
    {
        var currentDir = new DirectoryInfo(AppContext.BaseDirectory);
        while (currentDir != null)
        {
            var candidate = Path.Combine(currentDir.FullName, "tests", "Platform.UnitTests", "Fixtures", "sarif-schema-2.1.0.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            var direct = Path.Combine(currentDir.FullName, "Fixtures", "sarif-schema-2.1.0.json");
            if (File.Exists(direct))
            {
                return direct;
            }
            currentDir = currentDir.Parent;
        }
        throw new FileNotFoundException("Official SARIF 2.1.0 JSON schema fixture not found.");
    }
}
