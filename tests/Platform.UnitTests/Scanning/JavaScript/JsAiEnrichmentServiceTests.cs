using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class JsAiEnrichmentServiceTests
{
    private readonly JsAiEnrichmentService _service;

    public JsAiEnrichmentServiceTests()
    {
        _service = new JsAiEnrichmentService(NullLogger<JsAiEnrichmentService>.Instance);
    }

    [Fact]
    public void ProjectEvidence_RedactsSensitiveTokensAndBoundsSnippetLength()
    {
        var findingId = Guid.NewGuid();
        var rawSnippet = "const awsKey = 'AKIA1234567890ABCDEF'; const token = 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak'; " + new string('A', 800);

        var candidate = new FindingCandidate(
            ToolKey: "jsminer",
            ToolVersion: "1.2.0",
            FindingType: FindingType.UnvalidatedCredentialExposed,
            Title: "AWS Key Exposed",
            Description: rawSnippet,
            RawSeverity: "high",
            TargetUrl: "https://example.com/bundle.js",
            CweId: "CWE-798",
            EndpointPath: "/bundle.js",
            HttpMethod: "GET",
            ParameterName: "awsKey",
            RuleOrTemplateId: "exposed-aws-key",
            RawEvidenceJson: "{}",
            ObservedAtUtc: DateTime.UtcNow
        );

        var projected = AiEvidenceProjector.ProjectEvidence(findingId, candidate);

        Assert.Equal(findingId, projected.FindingId);
        Assert.DoesNotContain("AKIA1234567890ABCDEF", projected.SanitizedCodeSnippet);
        Assert.DoesNotContain("doNotLeak", projected.SanitizedCodeSnippet);
        Assert.Contains("[REDACTED_SECRET_", projected.SanitizedCodeSnippet);
        Assert.True(projected.SanitizedCodeSnippet.Length <= AiEvidenceProjector.MaxSnippetChars + 50);
    }

    [Fact]
    public async Task GenerateAdvisory_DomXssFinding_ProducesStructuredAdvisoryReport()
    {
        var findingId = Guid.NewGuid();
        var evidence = new ProjectedAiEvidence(
            FindingId: findingId,
            RuleOrTemplateId: "dom-xss-potential",
            FindingTitle: "Potential DOM-XSS",
            TargetEndpoint: "/app.js",
            HttpMethod: "GET",
            ParameterName: "location.hash",
            SanitizedCodeSnippet: "document.getElementById('out').innerHTML = location.hash;",
            SanitizedContextDetails: new Dictionary<string, string>(),
            PromptTokenEstimate: 30
        );

        var request = new JsAiAdvisoryRequest(evidence);
        var response = await _service.GenerateAdvisoryAsync(request);

        Assert.Equal(AiEnrichmentStatus.Success, response.Status);
        Assert.NotNull(response.AdvisoryReport);

        var report = response.AdvisoryReport;
        Assert.Equal(findingId, report.FindingId);
        Assert.True(report.IsAdvisoryOnly);
        Assert.Equal("1.0", report.PromptSchemaVersion);
        Assert.Contains("textContent", report.RecommendedRemediation);
        Assert.Contains("DOMPurify.sanitize", report.SuggestedCodeFix);
    }

    [Fact]
    public async Task GenerateAdvisory_SecretFinding_ProvidesRotationAndBackendProxyAdvice()
    {
        var findingId = Guid.NewGuid();
        var evidence = new ProjectedAiEvidence(
            FindingId: findingId,
            RuleOrTemplateId: "exposed-api-token",
            FindingTitle: "API Token Discovered",
            TargetEndpoint: "/config.js",
            HttpMethod: "GET",
            ParameterName: "api_key",
            SanitizedCodeSnippet: "const key = '[REDACTED_SECRET_TOKEN]';",
            SanitizedContextDetails: new Dictionary<string, string>(),
            PromptTokenEstimate: 20
        );

        var request = new JsAiAdvisoryRequest(evidence);
        var response = await _service.GenerateAdvisoryAsync(request);

        Assert.Equal(AiEnrichmentStatus.Success, response.Status);
        Assert.NotNull(response.AdvisoryReport);

        var report = response.AdvisoryReport;
        Assert.Contains("revoke", report.RecommendedRemediation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("environment variable", report.RecommendedRemediation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GenerateAdvisory_Timeout_ReturnsFailedTimeoutWithoutThrowing()
    {
        var findingId = Guid.NewGuid();
        var evidence = new ProjectedAiEvidence(
            FindingId: findingId,
            RuleOrTemplateId: "dom-xss-potential",
            FindingTitle: "Potential DOM-XSS",
            TargetEndpoint: "/app.js",
            HttpMethod: "GET",
            ParameterName: "location.hash",
            SanitizedCodeSnippet: "document.write(param);",
            SanitizedContextDetails: new Dictionary<string, string>(),
            PromptTokenEstimate: 10
        );

        // Pre-cancelled token to simulate instant timeout
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var request = new JsAiAdvisoryRequest(evidence, Timeout: TimeSpan.FromMilliseconds(1));
        var response = await _service.GenerateAdvisoryAsync(request, cts.Token);

        Assert.True(response.Status is AiEnrichmentStatus.FailedTimeout or AiEnrichmentStatus.FailedError);
        Assert.Null(response.AdvisoryReport);
    }

    [Fact]
    public async Task EnrichFindingCandidates_NonAuthoritative_LeavesFindingCandidatesUnmodified()
    {
        var candidate = new FindingCandidate(
            ToolKey: "jsminer",
            ToolVersion: "1.2.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: "Potential DOM-Based Cross-Site Scripting (DOM-XSS)",
            Description: "innerHTML flow from location.hash",
            RawSeverity: "medium",
            TargetUrl: "https://example.com/app.js",
            CweId: "CWE-79",
            EndpointPath: "/app.js",
            HttpMethod: "GET",
            ParameterName: "location.hash",
            RuleOrTemplateId: "dom-xss-potential",
            RawEvidenceJson: "{}",
            ObservedAtUtc: DateTime.UtcNow
        );

        var reports = await _service.EnrichFindingCandidatesAsync(new[] { candidate });

        Assert.Single(reports);
        Assert.Equal("dom-xss-potential", reports[0].RuleOrTemplateId);
        Assert.True(reports[0].IsAdvisoryOnly);

        // Candidate remains unchanged
        Assert.Equal("medium", candidate.RawSeverity);
        Assert.Equal(FindingType.ProductionServiceExposed, candidate.FindingType);
    }
}
