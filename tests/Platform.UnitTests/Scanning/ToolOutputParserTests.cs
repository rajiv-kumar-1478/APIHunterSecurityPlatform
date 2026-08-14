using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ToolOutputParserTests
{
    private readonly ScanJobContext _context = new(
        JobId: Guid.NewGuid(),
        RepositoryId: Guid.NewGuid(),
        TargetId: Guid.NewGuid(),
        TargetUrl: "https://api.example.com",
        ScanProfile: SecurityScanProfileType.Standard,
        JobStartedAtUtc: DateTime.UtcNow.AddMinutes(-5)
    );

    [Fact]
    public void NucleiOutputParser_ParsesRealisticJsonLines_Successfully()
    {
        var rawJsonLines =
            "{\"template-id\":\"cve-2021-41773\",\"info\":{\"name\":\"Apache 2.4.49 - Path Traversal and RCE\",\"severity\":\"critical\",\"description\":\"Path traversal in Apache HTTP Server 2.4.49\",\"classification\":{\"cve-id\":[\"CVE-2021-41773\"],\"cwe-id\":\"CWE-22\"}},\"type\":\"http\",\"host\":\"https://api.example.com\",\"matched-at\":\"https://api.example.com/icons/.%2e/%2e%2e/etc/passwd\",\"path\":\"/icons/.%2e/%2e%2e/etc/passwd\",\"extracted-results\":[\"root:x:0:0:root:/root:/bin/bash\"],\"timestamp\":\"2026-08-14T10:00:00Z\",\"matcher-name\":\"path-traversal-success\"}\n" +
            "{\"template-id\":\"git-config-exposure\",\"info\":{\"name\":\"Git Config Exposure\",\"severity\":\"medium\",\"description\":\".git/config accessible\"},\"type\":\"http\",\"host\":\"https://api.example.com\",\"matched-at\":\"https://api.example.com/.git/config\",\"path\":\"/.git/config\",\"timestamp\":\"2026-08-14T10:01:00Z\"}\n";

        var parser = new NucleiOutputParser();
        var candidates = parser.Parse(rawJsonLines, _context);

        candidates.Should().HaveCount(2);

        var first = candidates[0];
        first.ToolKey.Should().Be("nuclei");
        first.TemplateId.Should().Be("cve-2021-41773");
        first.Title.Should().Be("Apache 2.4.49 - Path Traversal and RCE");
        first.RawSeverity.Should().Be("critical");
        first.CveId.Should().Be("CVE-2021-41773");
        first.CweId.Should().Be("CWE-22");
        first.TargetUrl.Should().Be("https://api.example.com/icons/.%2e/%2e%2e/etc/passwd");
        first.ExtractedData.Should().Contain("root:x:0:0");
        first.Attributes.Should().ContainKey("matcher_name");

        var second = candidates[1];
        second.TemplateId.Should().Be("git-config-exposure");
        second.RawSeverity.Should().Be("medium");
    }

    [Fact]
    public void NucleiOutputParser_ParsesJsonArray_Successfully()
    {
        var rawJsonArray = "[{\"template-id\":\"swagger-api-docs\",\"info\":{\"name\":\"Swagger API Docs\",\"severity\":\"info\"},\"matched-at\":\"https://api.example.com/swagger/index.html\"}]";

        var parser = new NucleiOutputParser();
        var candidates = parser.Parse(rawJsonArray, _context);

        candidates.Should().HaveCount(1);
        candidates[0].TemplateId.Should().Be("swagger-api-docs");
        candidates[0].RawSeverity.Should().Be("info");
        candidates[0].TargetUrl.Should().Be("https://api.example.com/swagger/index.html");
    }

    [Fact]
    public void NucleiOutputParser_HandlesMalformedOutput_GracefullyWithoutCrashing()
    {
        var malformed = "{ this is completely malformed json }\n" +
                        "random garbage text that is not json\n" +
                        "{\"template-id\":\"valid-template\",\"info\":{\"name\":\"Valid Finding\",\"severity\":\"low\"},\"matched-at\":\"https://api.example.com/valid\"}\n";

        var parser = new NucleiOutputParser();
        var candidates = parser.Parse(malformed, _context);

        candidates.Should().HaveCount(1);
        candidates[0].TemplateId.Should().Be("valid-template");
    }

    [Fact]
    public void NucleiOutputParser_EnforcesCandidateLimitBound()
    {
        var lines = string.Join("\n", Enumerable.Range(1, 100).Select(i =>
            $"{{\"template-id\":\"vuln-{i}\",\"info\":{{\"name\":\"Vuln {i}\",\"severity\":\"low\"}},\"matched-at\":\"https://api.example.com/path-{i}\"}}"));

        var parser = new NucleiOutputParser();
        var bounds = new ParserResourceBounds(MaxCandidateCount: 15);

        var candidates = parser.Parse(lines, _context, bounds);
        candidates.Should().HaveCount(15, "Parser must strictly respect MaxCandidateCount bound");
    }

    [Fact]
    public void HttpxOutputParser_ParsesJsonLines_Successfully()
    {
        var rawJsonLines =
            "{\"url\":\"https://api.example.com\",\"input\":\"https://api.example.com\",\"title\":\"API Gateway Login\",\"status_code\":200,\"webserver\":\"nginx/1.20\",\"tech\":[\"Node.js\",\"Express\"],\"method\":\"GET\",\"path\":\"/\"}\n" +
            "{\"url\":\"https://admin.api.example.com/login\",\"input\":\"https://admin.api.example.com\",\"title\":\"Admin Portal\",\"status_code\":403,\"webserver\":\"Apache/2.4\",\"method\":\"GET\"}\n";

        var parser = new HttpxOutputParser();
        var candidates = parser.Parse(rawJsonLines, _context);

        candidates.Should().HaveCount(2);

        var first = candidates[0];
        first.ToolKey.Should().Be("httpx");
        first.TargetUrl.Should().Be("https://api.example.com");
        first.HttpResponseStatusCode.Should().Be(200);
        first.Title.Should().Contain("API Gateway Login");
        first.Attributes.Should().ContainKey("technologies");
        first.Attributes!["technologies"].Should().Contain("Node.js");

        var second = candidates[1];
        second.TargetUrl.Should().Be("https://admin.api.example.com/login");
        second.HttpResponseStatusCode.Should().Be(403);
    }

    [Fact]
    public void SubfinderOutputParser_ParsesJsonAndPlaintextLines_Successfully()
    {
        var rawOutput =
            "{\"host\":\"api.example.com\",\"source\":\"crtsh\",\"input\":\"example.com\"}\n" +
            "{\"host\":\"admin.api.example.com\",\"source\":\"alienvault\",\"input\":\"example.com\"}\n" +
            "staging.api.example.com\n";

        var parser = new SubfinderOutputParser();
        var candidates = parser.Parse(rawOutput, _context);

        candidates.Should().HaveCount(3);
        candidates[0].TargetUrl.Should().Be("https://api.example.com");
        candidates[0].Attributes!["source"].Should().Be("crtsh");

        candidates[1].TargetUrl.Should().Be("https://admin.api.example.com");
        candidates[1].Attributes!["source"].Should().Be("alienvault");

        candidates[2].TargetUrl.Should().Be("https://staging.api.example.com");
    }

    [Fact]
    public async Task EndToEnd_ParserToIngestion_Flow_ProducesAuthoritativeSecurityFindings()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        using var dbContext = new PlatformDbContext(options);

        // Seed repo
        dbContext.Repositories.Add(new Repository
        {
            Id = _context.RepositoryId,
            Name = "EndToEndTargetRepo",
            FullName = "org/EndToEndTargetRepo",
            Owner = "org",
            Url = "https://github.com/org/EndToEndTargetRepo",
            CreatedAtUtc = DateTime.UtcNow
        });
        await dbContext.SaveChangesAsync();

        var rawNucleiOutput =
            "{\"template-id\":\"cve-2021-41773\",\"info\":{\"name\":\"Apache Path Traversal RCE\",\"severity\":\"critical\",\"classification\":{\"cve-id\":[\"CVE-2021-41773\"]}},\"matched-at\":\"https://api.example.com/icons/.%2e/etc/passwd\",\"path\":\"/icons/.%2e/etc/passwd\",\"extracted-results\":[\"root:x:0:0:root:/root:/bin/bash\"]}\n";

        var parser = new NucleiOutputParser();
        var candidates = parser.Parse(rawNucleiOutput, _context);

        var ingestionEngine = new ScanFindingIngestionEngine(dbContext, NullLogger<ScanFindingIngestionEngine>.Instance);
        var result = await ingestionEngine.IngestCandidatesAsync(candidates, _context);

        result.CandidatesAccepted.Should().Be(1);
        result.NewFindingsCreated.Should().Be(1);

        var savedFinding = await dbContext.SecurityFindings.Include(f => f.Evidences).FirstAsync();
        savedFinding.Title.Should().Be("Apache Path Traversal RCE");
        savedFinding.RiskScore.Should().BeGreaterThan(0, "Platform Risk Engine must calculate authoritative score");
        savedFinding.RiskFactorBreakdownJson.Should().Contain("INTERNET_FACING");
        savedFinding.Status.Should().Be(FindingStatus.Open);
        savedFinding.Evidences.Should().HaveCount(1);
        savedFinding.Evidences.First().SafeEvidenceJson.Should().Contain("cve-2021-41773");
        savedFinding.Evidences.First().SafeEvidenceJson.Should().Contain("critical");
    }
}
