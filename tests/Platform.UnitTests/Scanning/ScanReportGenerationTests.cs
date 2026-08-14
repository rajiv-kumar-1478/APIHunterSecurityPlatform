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

        root.GetProperty("$schema").GetString().Should().Contain("sarif-schema-2.1.0.json");
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

    private static readonly Lazy<Json.Schema.JsonSchema> OfficialSarifSchema = new(() =>
    {
        var schemaPath = GetOfficialSarifSchemaPath();
        var schemaJson = System.IO.File.ReadAllText(schemaPath);
        return Json.Schema.JsonSchema.FromText(schemaJson);
    });

    [Fact]
    public async Task SarifOutput_ValidatesAgainstOfficialOasisSarif210Schema()
    {
        var (job, findings) = await SeedScanWithFindingsAsync();
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);
        var sarifResult = _registry.GetFormatter("sarif").FormatReport(canonicalReport);

        using var doc = JsonDocument.Parse(sarifResult.Content);

        var schema = OfficialSarifSchema.Value;
        var evaluation = schema.Evaluate(doc.RootElement, new Json.Schema.EvaluationOptions
        {
            OutputFormat = Json.Schema.OutputFormat.List
        });

        if (!evaluation.IsValid)
        {
            var errors = string.Join("; ", evaluation.Details.SelectMany(d => d.Errors ?? new Dictionary<string, string>()).Select(kv => $"{kv.Key}: {kv.Value}"));
            throw new Exception($"SARIF Schema Evaluation Failed: {errors}\n\nGenerated SARIF:\n{sarifResult.Content}");
        }

        evaluation.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task SarifOutput_MalformedSarifFailsOfficialSchemaValidation()
    {
        var malformedSarif = """
        {
          "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
          "version": "1.0.0",
          "runs": [
            {
              "tool": {}
            }
          ]
        }
        """;

        using var doc = JsonDocument.Parse(malformedSarif);
        var schema = OfficialSarifSchema.Value;
        var evaluation = schema.Evaluate(doc.RootElement);
        evaluation.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task FormatterRegistry_EnforcesMaxOutputCeiling_FailsClosedWhenExceeded()
    {
        var (job, findings) = await SeedScanWithFindingsAsync();
        var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(job.Id);

        // Register an oversized mock formatter that produces > 20 MiB
        var oversizedFormatter = new Mock<ISecurityReportFormatter>();
        oversizedFormatter.Setup(f => f.Format).Returns(SecurityReportFormat.Json);
        oversizedFormatter.Setup(f => f.ContentType).Returns("application/json");
        oversizedFormatter.Setup(f => f.FileExtension).Returns("oversized");
        oversizedFormatter.Setup(f => f.FormatReport(It.IsAny<CanonicalSecurityReport>()))
            .Returns(new FormattedReportResult(new string('X', 21 * 1024 * 1024), "application/json", "oversized.json"));

        var customRegistry = new SecurityReportFormatterRegistry(new[] { oversizedFormatter.Object });

        Action act = () => customRegistry.FormatReport("oversized", canonicalReport);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*exceeds maximum ceiling of 20971520 bytes*");
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

        // Deterministic check: Multiple report generations for the same scan job produce identical ProvenanceSignature
        report1.Metadata.ProvenanceSignature.Should().Be(report2.Metadata.ProvenanceSignature);

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
    public async Task BoundedReport_CapsFindingsAtResourceCeiling()
    {
        var (job, _) = await SeedScanWithFindingsAsync();

        var extraFindings = new List<SecurityFinding>();
        var extraObs = new List<ScanFindingObservation>();
        for (int i = 0; i < 1100; i++)
        {
            var f = new SecurityFinding
            {
                Id = Guid.NewGuid(),
                RepositoryId = _repoId,
                FindingFingerprint = $"extra_fp_{i}",
                FindingType = FindingType.ProductionServiceExposed,
                Severity = RiskSeverity.Low,
                RiskScore = 20,
                Title = $"Extra finding {i}",
                Status = FindingStatus.Open,
                CreatedAtUtc = DateTime.UtcNow
            };
            extraFindings.Add(f);
            extraObs.Add(new ScanFindingObservation
            {
                FindingId = f.Id,
                ScanJobId = job.Id,
                WasObserved = true,
                FullCoverageConfirmed = true,
                ToolCoverageHash = "coverage_abc"
            });
        }
        _dbContext.SecurityFindings.AddRange(extraFindings);
        _dbContext.ScanFindingObservations.AddRange(extraObs);
        await _dbContext.SaveChangesAsync();

        var report = await _reportBuilder.BuildCanonicalReportAsync(job.Id);
        report.Findings.Count.Should().BeLessThanOrEqualTo(ReportResourceBounds.MaxReportFindings);
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

    private static string GetOfficialSarifSchemaPath()
    {
        var currentDir = new System.IO.DirectoryInfo(AppContext.BaseDirectory);
        while (currentDir != null)
        {
            var candidate = System.IO.Path.Combine(currentDir.FullName, "tests", "Platform.UnitTests", "Fixtures", "sarif-schema-2.1.0.json");
            if (System.IO.File.Exists(candidate))
            {
                return candidate;
            }
            var direct = System.IO.Path.Combine(currentDir.FullName, "Fixtures", "sarif-schema-2.1.0.json");
            if (System.IO.File.Exists(direct))
            {
                return direct;
            }
            currentDir = currentDir.Parent;
        }
        throw new System.IO.FileNotFoundException("Official SARIF 2.1.0 JSON schema fixture not found.");
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
