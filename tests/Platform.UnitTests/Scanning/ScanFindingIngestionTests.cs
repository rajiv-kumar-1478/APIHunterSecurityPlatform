using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Configuration;
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

        var riskPolicy = new RiskPolicyOptions
        {
            WeightInternetFacingService = 15,
            WeightProductionEnvironment = 20
        };
        var riskEngine = new RiskEngine(riskPolicy);

        _engine = new ScanFindingIngestionEngine(_dbContext, NullLogger<ScanFindingIngestionEngine>.Instance, riskEngine);
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
    public async Task Ingestion_DeduplicatesAcrossMultipleTools_AppendsEvidence_AndCalculatesAuthoritativeRisk()
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

        var firstFinding = await _dbContext.SecurityFindings.AsNoTracking().Include(f => f.Evidences).FirstAsync();
        firstFinding.RiskScore.Should().BeGreaterThan(0, "Risk Engine must calculate authoritative risk score");
        firstFinding.RiskFactorBreakdownJson.Should().Contain("INTERNET_FACING");

        // 2. Ingest from Tool B
        var res2 = await _engine.IngestCandidatesAsync(new[] { customScannerCandidate }, _context);
        res2.NewFindingsCreated.Should().Be(0);
        res2.ExistingFindingsUpdated.Should().Be(1, "Second tool output must match identical finding fingerprint idempotently");

        // Verify finding has 2 distinct evidence attachments (evidence append, not overwrite)
        var findings = await _dbContext.SecurityFindings.AsNoTracking().Include(f => f.Evidences).ToListAsync();
        findings.Should().HaveCount(1);
        findings[0].Evidences.Should().HaveCount(2, "Both tool observations must be preserved in finding evidence");
        findings[0].Evidences.Should().Contain(e => e.SafeEvidenceJson.Contains("nuclei"));
        findings[0].Evidences.Should().Contain(e => e.SafeEvidenceJson.Contains("bughunter_custom"));

        // Verify Audit Event was recorded
        var auditEvents = await _dbContext.AuditEvents.Where(a => a.EventCode == AuditEventCode.ScanFindingsIngested).ToListAsync();
        auditEvents.Should().HaveCount(2);
    }

    [Fact]
    public async Task Ingestion_SanitizesAdversarialAndHostileInputs_Gracefully()
    {
        var longTitle = new string('A', 500); // Exceeds 256 char limit
        var hostilePayload = "Leaked token Bearer secret_live_jwt_token_1234567890 \x00\x01 with api_key=\"live_master_api_key_88888888\"";

        var adversarialCandidates = new List<FindingCandidate>
        {
            // 1. Oversized title & embedded secrets
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: longTitle,
                Description: hostilePayload,
                RawSeverity: "high",
                TargetUrl: "https://api.example.com/v1/debug?token=sensitive_query_token_12345",
                ExtractedData: hostilePayload,
                Attributes: new Dictionary<string, string>
                {
                    ["auth_header"] = "Bearer secret_live_jwt_token_1234567890",
                    ["clean_key"] = "safe_value"
                }
            ),
            // 2. Javascript scheme injection -> Must be rejected by scope check
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "XSS Javascript URI",
                Description: "Javascript pseudo-protocol",
                RawSeverity: "medium",
                TargetUrl: "javascript:alert(1)"
            ),
            // 3. Localhost / Internal IP redirection -> Must be rejected by scope check
            new(
                ToolKey: "nuclei",
                ToolVersion: "v3.1.0",
                FindingType: FindingType.ProductionServiceExposed,
                Title: "SSRF to localhost",
                Description: "Internal probe",
                RawSeverity: "critical",
                TargetUrl: "http://127.0.0.1:8080/admin"
            )
        };

        var result = await _engine.IngestCandidatesAsync(adversarialCandidates, _context);

        result.CandidatesAccepted.Should().Be(1);
        result.OutOfScopeDiscarded.Should().Be(2);

        var finding = await _dbContext.SecurityFindings.Include(f => f.Evidences).FirstAsync();
        finding.Title.Length.Should().BeLessThanOrEqualTo(256, "Oversized titles must be truncated to column bounds");
        finding.Description.Should().NotContain("secret_live_jwt_token_1234567890");
        finding.Description.Should().NotContain("live_master_api_key_88888888");
        finding.Description.Should().NotContain("\x00");

        var evidence = finding.Evidences.First();
        evidence.EvidenceReference.Should().NotContain("sensitive_query_token_12345");
        evidence.EvidenceReference.Should().Contain("token=[REDACTED]");
        evidence.SafeEvidenceJson.Should().NotContain("secret_live_jwt_token_1234567890");
    }

    [Fact]
    public async Task Ingestion_NormalizesSeverity_AndAuditsUnknownSeverities()
    {
        // 1. Direct NormalizeSeverity unit tests
        ScanFindingIngestionEngine.NormalizeSeverity("critical").Severity.Should().Be(RiskSeverity.Critical);
        ScanFindingIngestionEngine.NormalizeSeverity("HIGH").Severity.Should().Be(RiskSeverity.High);
        ScanFindingIngestionEngine.NormalizeSeverity("medium").Severity.Should().Be(RiskSeverity.Medium);
        ScanFindingIngestionEngine.NormalizeSeverity("low").Severity.Should().Be(RiskSeverity.Low);
        ScanFindingIngestionEngine.NormalizeSeverity("info").Severity.Should().Be(RiskSeverity.Info);

        var unknown = ScanFindingIngestionEngine.NormalizeSeverity("SUPER_EXTREME_URGENT");
        unknown.Severity.Should().Be(RiskSeverity.Info);
        unknown.FallbackApplied.Should().BeTrue();

        // 2. Ingestion with unknown severity records diagnostic and persists evidence
        var candidates = new List<FindingCandidate>
        {
            new("t1", "1.0", FindingType.ProductionServiceExposed, "Unknown Severity Bug", "Desc", "SUPER_EXTREME_URGENT", "https://api.example.com/endpoint")
        };

        var result = await _engine.IngestCandidatesAsync(candidates, _context);
        result.CandidatesAccepted.Should().Be(1);
        result.Diagnostics.Should().Contain(d => d.Contains("SUPER_EXTREME_URGENT") && d.Contains("Info"));

        var finding = await _dbContext.SecurityFindings.Include(f => f.Evidences).FirstAsync(f => f.Title == "Unknown Severity Bug");
        finding.RiskScore.Should().BeGreaterThan(0);
        finding.Evidences.First().SafeEvidenceJson.Should().Contain("SUPER_EXTREME_URGENT");
    }
}
