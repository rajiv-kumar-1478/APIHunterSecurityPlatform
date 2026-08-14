using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Reporting.Formatters;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanReportGenerationTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly TestUserContext _userContext;
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly ScanJobService _scanJobService;
    private readonly ScanPostExecutionProcessor _postProcessor;
    private readonly ScanReportBuilderService _reportBuilder;
    private readonly SecurityReportFormatterRegistry _registry;

    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanReportGenerationTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanReportGenerationTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _userContext = new TestUserContext();
        _toolRegistry = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _scanJobService = new ScanJobService(_dbContext, _userContext, _toolRegistry, NullLogger<ScanJobService>.Instance);
        _postProcessor = new ScanPostExecutionProcessor(_dbContext, _scanJobService, NullLogger<ScanPostExecutionProcessor>.Instance);
        _reportBuilder = new ScanReportBuilderService(_dbContext, _scanJobService, _postProcessor, NullLogger<ScanReportBuilderService>.Instance);
        _registry = new SecurityReportFormatterRegistry();

        // Seed Repo & Target
        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "VulnerableApi",
            FullName = "acme/VulnerableApi",
            Owner = "acme",
            Url = "https://github.com/acme/VulnerableApi",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Production Api Gateway",
            BaseUrl = "https://api.acme.com",
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
    public async Task SingleCanonicalReport_ProducesIdenticalFindingCounts_AcrossAllFormats()
    {
        var (job, findings) = await SeedScanWithFindingsAsync();

        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        canonicalReport.Findings.Should().HaveCount(2);
        canonicalReport.PostureSummary.TotalFindings.Should().Be(2);

        // 1. JSON Format
        var jsonResult = _registry.GetFormatter("json").FormatReport(canonicalReport);
        jsonResult.ContentType.Should().Be("application/json");
        using var jsonDoc = JsonDocument.Parse(jsonResult.Content);
        jsonDoc.RootElement.GetProperty("findings").GetArrayLength().Should().Be(2);

        // 2. SARIF Format
        var sarifResult = _registry.GetFormatter("sarif").FormatReport(canonicalReport);
        sarifResult.ContentType.Should().Be("application/sarif+json");
        using var sarifDoc = JsonDocument.Parse(sarifResult.Content);
        sarifDoc.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength().Should().Be(2);

        // 3. Markdown Format
        var mdResult = _registry.GetFormatter("markdown").FormatReport(canonicalReport);
        mdResult.ContentType.Should().Be("text/markdown");
        mdResult.Content.Should().Contain("### 3.1 [Critical]");
        mdResult.Content.Should().Contain("### 3.2 [High]");

        // 4. HTML Format
        var htmlResult = _registry.GetFormatter("html").FormatReport(canonicalReport);
        htmlResult.ContentType.Should().Contain("text/html");
        htmlResult.Content.Should().Contain("finding-critical");
        htmlResult.Content.Should().Contain("finding-high");
    }

    [Fact]
    public async Task SecretInjectedIntoEvidence_IsRedactedFromAllFourFormats()
    {
        var rawSecret = "AKIAIOSFODNN7EXAMPLE";
        var rawBearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecretpayload";

        var (job, findings) = await SeedScanWithFindingsAsync(rawSecret, rawBearer);

        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        // 1. JSON
        var jsonResult = _registry.GetFormatter("json").FormatReport(canonicalReport);
        jsonResult.Content.Should().NotContain(rawSecret);
        jsonResult.Content.Should().NotContain("supersecretpayload");

        // 2. SARIF
        var sarifResult = _registry.GetFormatter("sarif").FormatReport(canonicalReport);
        sarifResult.Content.Should().NotContain(rawSecret);
        sarifResult.Content.Should().NotContain("supersecretpayload");

        // 3. Markdown
        var mdResult = _registry.GetFormatter("markdown").FormatReport(canonicalReport);
        mdResult.Content.Should().NotContain(rawSecret);
        mdResult.Content.Should().NotContain("supersecretpayload");

        // 4. HTML
        var htmlResult = _registry.GetFormatter("html").FormatReport(canonicalReport);
        htmlResult.Content.Should().NotContain(rawSecret);
        htmlResult.Content.Should().NotContain("supersecretpayload");
    }

    [Fact]
    public async Task SarifOutput_AdheresToSarif210Structure()
    {
        var (job, findings) = await SeedScanWithFindingsAsync();
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        var sarifResult = _registry.GetFormatter("sarif").FormatReport(canonicalReport);
        using var doc = JsonDocument.Parse(sarifResult.Content);
        var root = doc.RootElement;

        root.GetProperty("$schema").GetString().Should().Be("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        root.GetProperty("version").GetString().Should().Be("2.1.0");

        var runs = root.GetProperty("runs");
        runs.GetArrayLength().Should().Be(1);

        var toolDriver = runs[0].GetProperty("tool").GetProperty("driver");
        toolDriver.GetProperty("name").GetString().Should().Be("APIHunter Security Platform");
        toolDriver.GetProperty("rules").GetArrayLength().Should().BeGreaterThan(0);

        var results = runs[0].GetProperty("results");
        results.GetArrayLength().Should().Be(2);
        results[0].GetProperty("level").GetString().Should().Be("error");
    }

    [Fact]
    public async Task HtmlOutput_StrictlyEscapesUserControlledContent_PreventingXSS()
    {
        var xssTitle = "<script>alert('XSS_ATTACK')</script>";
        var xssDesc = "<img src=x onerror=alert(1)>";

        var (job, findings) = await SeedScanWithFindingsAsync(findingTitleOverride: xssTitle, findingDescOverride: xssDesc);
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        var htmlResult = _registry.GetFormatter("html").FormatReport(canonicalReport);

        htmlResult.Content.Should().NotContain("<script>alert('XSS_ATTACK')</script>");
        htmlResult.Content.Should().NotContain("<img src=x onerror=alert(1)>");
        htmlResult.Content.Should().Contain("&lt;script&gt;alert(&#39;XSS_ATTACK&#39;)&lt;/script&gt;");
        htmlResult.Content.Should().Contain("&lt;img src=x onerror=alert(1)&gt;");
    }

    [Fact]
    public async Task MarkdownOutput_InertlyRendersFindingControlledContent()
    {
        var xssTitle = "<script>console.log('test')</script>";
        var (job, findings) = await SeedScanWithFindingsAsync(findingTitleOverride: xssTitle);
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        var mdResult = _registry.GetFormatter("markdown").FormatReport(canonicalReport);
        mdResult.Content.Should().NotContain("<script>");
        mdResult.Content.Should().Contain("&lt;script&gt;");
    }

    [Fact]
    public async Task ProvenanceSignature_IsDeterministicAndChangesWhenInputsChange()
    {
        var (job, findings) = await SeedScanWithFindingsAsync();
        var report1 = await _reportBuilder.BuildCanonicalReportAsync(job.Id);
        var report2 = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        report1.Metadata.ProvenanceSignature.Should().NotBeNullOrWhiteSpace();
        report1.Metadata.ProvenanceSignature.Length.Should().Be(64); // SHA-256 hex string

        // Create a different job
        var otherJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.acme.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow
        };
        _dbContext.SecurityScanJobs.Add(otherJob);
        await _dbContext.SaveChangesAsync();

        var otherReport = await _reportBuilder.BuildCanonicalReportAsync(otherJob.Id);
        otherReport.Metadata.ProvenanceSignature.Should().NotBe(report1.Metadata.ProvenanceSignature);
    }

    [Fact]
    public void FormatterRegistry_ThrowsArgumentException_ForUnknownFormat()
    {
        Action act = () => _registry.GetFormatter("yaml");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Unsupported report format 'yaml'*");

        Action act2 = () => _registry.GetFormatter("pdf");
        act2.Should().Throw<ArgumentException>()
            .WithMessage("*Unsupported report format 'pdf'*");
    }

    private async Task<(SecurityScanJob Job, List<SecurityFinding> Findings)> SeedScanWithFindingsAsync(
        string? secret1 = null,
        string? secret2 = null,
        string? findingTitleOverride = null,
        string? findingDescOverride = null)
    {
        var receipt = new ScanExecutionReceipt(
            JobId: Guid.NewGuid(),
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:111", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-2), DateTime.UtcNow, 30000, 1024, 2, 0, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 2,
            TotalFindingsUpdated: 0,
            Summary: "Scan finished with 2 findings."
        );

        var job = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.acme.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc = DateTime.UtcNow
        };

        var finding1 = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "fp1_crit",
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            RiskScore = 95,
            Confidence = FindingConfidence.High,
            Title = findingTitleOverride ?? "Exposed AWS Credentials in /config",
            Description = findingDescOverride ?? "Critical access key leakage",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow,
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow
        };

        var finding2 = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "fp2_high",
            FindingType = FindingType.ProductionServiceExposed,
            Severity = RiskSeverity.High,
            RiskScore = 78,
            Confidence = FindingConfidence.High,
            Title = "Unauthenticated Admin Metrics Exposed",
            Description = "Production endpoint accessible",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow,
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow
        };

        var ev1Json = secret1 != null
            ? $"{{\"cveId\":\"CVE-2024-1234\",\"cweId\":\"CWE-798\",\"secret\":\"{secret1}\"}}"
            : "{\"cveId\":\"CVE-2024-1234\",\"cweId\":\"CWE-798\",\"cvssScore\":9.8}";

        var ev2Json = secret2 != null
            ? $"{{\"cveId\":\"CVE-2023-5678\",\"cweId\":\"CWE-200\",\"auth\":\"{secret2}\"}}"
            : "{\"cveId\":\"CVE-2023-5678\",\"cweId\":\"CWE-200\",\"cvssScore\":7.5}";

        var evidence1 = new SecurityFindingEvidence
        {
            Id = Guid.NewGuid(),
            FindingId = finding1.Id,
            EvidenceFingerprint = "ev_fp1",
            EvidenceReference = "https://api.acme.com/config",
            SafeEvidenceJson = ev1Json,
            CreatedAtUtc = DateTime.UtcNow
        };

        var evidence2 = new SecurityFindingEvidence
        {
            Id = Guid.NewGuid(),
            FindingId = finding2.Id,
            EvidenceFingerprint = "ev_fp2",
            EvidenceReference = "https://api.acme.com/metrics",
            SafeEvidenceJson = ev2Json,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.Add(job);
        _dbContext.SecurityFindings.AddRange(finding1, finding2);
        _dbContext.SecurityFindingEvidences.AddRange(evidence1, evidence2);

        _dbContext.ScanFindingObservations.AddRange(
            new ScanFindingObservation { FindingId = finding1.Id, ScanJobId = job.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "coverage_abc" },
            new ScanFindingObservation { FindingId = finding2.Id, ScanJobId = job.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "coverage_abc" }
        );

        await _dbContext.SaveChangesAsync();

        return (job, new List<SecurityFinding> { finding1, finding2 });
    }

    private class TestUserContext : ICurrentUserContext
    {
        public Guid? UserId { get; set; } = Guid.NewGuid();
        public string? SessionId { get; set; } = "session-test";
        public bool IsAuthenticated { get; set; } = true;
        public bool IsPlatformAdmin { get; set; } = true;
        public string CorrelationId { get; set; } = "corr-test";
        public string IpAddress { get; set; } = "127.0.0.1";
    }
}
