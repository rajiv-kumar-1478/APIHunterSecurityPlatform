using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanFindingIngestionTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanFindingIngestionEngine _engine;
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();
    private readonly ScanJobContext _context;

    public ScanFindingIngestionTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new PlatformDbContext(options);

        // Seed Repository & SecurityTarget
        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "SecurityScannerTargetRepo",
            FullName = "org/SecurityScannerTargetRepo",
            Owner = "org",
            Url = "https://github.com/org/SecurityScannerTargetRepo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Authorized Production API Target",
            TargetType = "WebEndpoint",
            BaseUrl = "https://api.example.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();

        _context = new ScanJobContext(
            JobId: Guid.NewGuid(),
            RepositoryId: _repoId,
            TargetId: _targetId,
            TargetUrl: "https://api.example.com",
            ScanProfile: SecurityScanProfileType.Standard,
            JobStartedAtUtc: DateTime.UtcNow.AddMinutes(-5)
        );

        _engine = new ScanFindingIngestionEngine(_dbContext, NullLogger<ScanFindingIngestionEngine>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task Ingestion_AcceptsInScopeTargets_AndRejectsSpoofedOrOutOfScopeTargets()
    {
        var candidates = new List<FindingCandidate>
        {
            // 1. Exact match in-scope
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "Exposed API Endpoint",
                Description: "Swagger docs publicly reachable",
                RawSeverity: "medium",
                TargetUrl: "https://api.example.com/swagger/index.html"
            ),
            // 2. Authorized subdomain in-scope
            new(
                ToolKey: "httpx",
                ToolVersion: "v1.4.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "Subdomain Admin Portal Exposed",
                Description: "Internal admin portal",
                RawSeverity: "high",
                TargetUrl: "https://admin.api.example.com/login"
            ),
            // 3. Spoofed suffix domain (evil-api.example.com) -> MUST BE REJECTED
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "Malicious Spoofed Host Finding",
                Description: "Attacker controlled spoofed domain",
                RawSeverity: "critical",
                TargetUrl: "https://evil-api.example.com/phishing"
            ),
            // 4. Foreign domain (attacker.com) -> MUST BE REJECTED
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "Foreign Host Finding",
                Description: "Unrelated foreign domain",
                RawSeverity: "high",
                TargetUrl: "https://attacker.com/exploit"
            )
        };

        var result = await _engine.IngestCandidatesAsync(candidates, _context);

        result.TotalCandidatesReceived.Should().Be(4);
        result.CandidatesAccepted.Should().Be(2);
        result.OutOfScopeDiscarded.Should().Be(2);
        result.NewFindingsCreated.Should().Be(2);

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        findings.Should().HaveCount(2);
        findings.Should().NotContain(f => f.Title.Contains("Spoofed") || f.Title.Contains("Foreign"));
    }

    [Fact]
    public async Task Ingestion_DeduplicatesAcrossMultipleTools_UsingToolAgnosticFingerprint()
    {
        // Tool A (Nuclei) reports CVE-2021-41773 on api.example.com
        var nucleiCandidate = new FindingCandidate(
            ToolKey: "nuclei",
            ToolVersion: "v3.1.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: "Apache Path Traversal Vulnerability",
            Description: "Path traversal leading to RCE",
            RawSeverity: "critical",
            TargetUrl: "https://api.example.com/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
            CveId: "CVE-2021-41773",
            EndpointPath: "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"
        );

        // Tool B (Custom Scanner) reports the SAME CVE on the SAME endpoint
        var customScannerCandidate = new FindingCandidate(
            ToolKey: "bughunter_custom",
            ToolVersion: "v2.0.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: "Apache HTTP Server Path Traversal (CVE-2021-41773)",
            Description: "Duplicate observation by separate engine",
            RawSeverity: "critical",
            TargetUrl: "https://api.example.com/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
            CveId: "CVE-2021-41773",
            EndpointPath: "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"
        );

        // 1. Ingest from Tool A
        var res1 = await _engine.IngestCandidatesAsync(new[] { nucleiCandidate }, _context);
        res1.NewFindingsCreated.Should().Be(1);
        res1.ExistingFindingsUpdated.Should().Be(0);

        // 2. Ingest from Tool B
        var res2 = await _engine.IngestCandidatesAsync(new[] { customScannerCandidate }, _context);
        res2.NewFindingsCreated.Should().Be(0);
        res2.ExistingFindingsUpdated.Should().Be(1, "Second tool output must match identical finding fingerprint idempotently");

        // Verify total finding count is 1 with 2 evidence attachments
        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        findings.Should().HaveCount(1);
        findings[0].Evidences.Should().HaveCount(2);
        findings[0].Evidences.Should().Contain(e => e.SafeEvidenceJson.Contains("nuclei"));
        findings[0].Evidences.Should().Contain(e => e.SafeEvidenceJson.Contains("bughunter_custom"));
    }

    [Fact]
    public async Task Ingestion_EnforcesStrictLifecycleLock_AndZeroAuthoritativeRiskInjection()
    {
        var candidate = new FindingCandidate(
            ToolKey: "nuclei",
            ToolVersion: "v3.1.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: "Exposed Metrics Endpoint",
            Description: "Prometheus metrics exposed",
            RawSeverity: "low",
            TargetUrl: "https://api.example.com/metrics"
        );

        var result = await _engine.IngestCandidatesAsync(new[] { candidate }, _context);
        result.NewFindingsCreated.Should().Be(1);

        var finding = await _dbContext.SecurityFindings.FirstAsync();
        finding.Status.Should().Be(FindingStatus.Open, "New findings must strictly initialize to Open");
        finding.LifecycleVersion.Should().Be(1);
        finding.RiskScore.Should().Be(0, "Tool cannot inject risk score; RiskScore remains 0 until Risk Engine evaluation");
    }

    [Fact]
    public async Task Ingestion_NormalizesSeverity_AndAuditsUnknownSeverities()
    {
        var candidates = new List<FindingCandidate>
        {
            new("t1", "1.0", FindingType.ProductionServiceExposed, "Crit Bug", "Desc", "critical", "https://api.example.com/1"),
            new("t2", "1.0", FindingType.ProductionServiceExposed, "High Bug", "Desc", "HIGH", "https://api.example.com/2"),
            new("t3", "1.0", FindingType.ProductionServiceExposed, "Med Bug", "Desc", "medium", "https://api.example.com/3"),
            new("t4", "1.0", FindingType.ProductionServiceExposed, "Low Bug", "Desc", "low", "https://api.example.com/4"),
            new("t5", "1.0", FindingType.ProductionServiceExposed, "Unknown Bug", "Desc", "SUPER_EXTREME_URGENT", "https://api.example.com/5")
        };

        var result = await _engine.IngestCandidatesAsync(candidates, _context);
        result.CandidatesAccepted.Should().Be(5);
        result.Diagnostics.Should().Contain(d => d.Contains("SUPER_EXTREME_URGENT") && d.Contains("Info"));

        var findings = await _dbContext.SecurityFindings.OrderBy(f => f.Title).ToListAsync();
        findings.First(f => f.Title == "Crit Bug").Severity.Should().Be(RiskSeverity.Critical);
        findings.First(f => f.Title == "High Bug").Severity.Should().Be(RiskSeverity.High);
        findings.First(f => f.Title == "Med Bug").Severity.Should().Be(RiskSeverity.Medium);
        findings.First(f => f.Title == "Low Bug").Severity.Should().Be(RiskSeverity.Low);
        findings.First(f => f.Title == "Unknown Bug").Severity.Should().Be(RiskSeverity.Info);
    }

    [Fact]
    public void EvidenceSanitizer_MasksCredentials_AndStripsDangerousCharacters()
    {
        var rawEvidence = "Found token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken12345 " +
                          "and api_key=\"secret_live_apikey_9999999\" in payload \x00\x01\x02 test.";

        var sanitized = EvidenceSanitizer.SanitizeEvidence(rawEvidence);

        sanitized.Should().NotContain("doNotLeakThisToken12345");
        sanitized.Should().NotContain("secret_live_apikey_9999999");
        sanitized.Should().NotContain("\x00");
        sanitized.Should().Contain("Bearer [REDACTED_TOKEN]");
        sanitized.Should().Contain("api_key=\"[REDACTED]\"");
    }

    [Fact]
    public void EvidenceSanitizer_RedactsSensitiveQueryParams_InUrls()
    {
        var url = "https://api.example.com/v1/auth/callback?code=abc12345&token=super_secret_jwt_token_999&state=xyz";
        var sanitized = EvidenceSanitizer.SanitizeUrl(url);

        sanitized.Should().NotContain("super_secret_jwt_token_999");
        sanitized.Should().Contain("token=[REDACTED]");
        sanitized.Should().Contain("code=abc12345");
        sanitized.Should().Contain("state=xyz");
    }
}
