using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative non-authoritative AI Advisory Enrichment service providing human-readable explanations,
/// threat scenarios, false-positive nuances, and code-level remediation suggestions.
/// </summary>
public sealed class JsAiEnrichmentService : IJsAiEnrichmentService
{
    public const string DefaultModelIdentifier = "gemini-1.5-flash";
    public const string CurrentPromptSchemaVersion = "1.0";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly ILogger<JsAiEnrichmentService> _logger;

    public JsAiEnrichmentService(ILogger<JsAiEnrichmentService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<JsAiEnrichmentResponse> GenerateAdvisoryAsync(
        JsAiAdvisoryRequest request,
        CancellationToken ct = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var stopwatch = Stopwatch.StartNew();
        var timeout = request.Timeout ?? DefaultTimeout;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        try
        {
            // Simulate AI reasoning over projected evidence (with cancellation support)
            await Task.Delay(10, cts.Token);

            var report = BuildAdvisoryReport(request.Evidence, request.PreferredModel ?? DefaultModelIdentifier);

            stopwatch.Stop();
            _logger.LogInformation("Generated AI advisory for finding '{FindingId}' (Rule: {Rule}) in {Elapsed}ms.",
                request.Evidence.FindingId, request.Evidence.RuleOrTemplateId, stopwatch.ElapsedMilliseconds);

            return new JsAiEnrichmentResponse(
                Status: AiEnrichmentStatus.Success,
                AdvisoryReport: report,
                ErrorMessage: null,
                DurationMs: stopwatch.ElapsedMilliseconds
            );
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            _logger.LogWarning("AI advisory generation timed out ({Timeout}s) for finding '{FindingId}'. Scan continues unaffected.",
                timeout.TotalSeconds, request.Evidence.FindingId);

            return new JsAiEnrichmentResponse(
                Status: AiEnrichmentStatus.FailedTimeout,
                AdvisoryReport: null,
                ErrorMessage: "AI advisory service timed out.",
                DurationMs: stopwatch.ElapsedMilliseconds
            );
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogWarning(ex, "AI advisory generation encountered an error for finding '{FindingId}'. Scan continues unaffected.",
                request.Evidence.FindingId);

            return new JsAiEnrichmentResponse(
                Status: AiEnrichmentStatus.FailedError,
                AdvisoryReport: null,
                ErrorMessage: ex.Message,
                DurationMs: stopwatch.ElapsedMilliseconds
            );
        }
    }

    public async Task<IReadOnlyList<JsAiAdvisoryReport>> EnrichFindingCandidatesAsync(
        IReadOnlyList<FindingCandidate> candidates,
        CancellationToken ct = default)
    {
        if (candidates == null || candidates.Count == 0)
        {
            return Array.Empty<JsAiAdvisoryReport>();
        }

        var reports = new List<JsAiAdvisoryReport>();

        foreach (var candidate in candidates)
        {
            var findingId = Guid.NewGuid();
            var projectedEvidence = AiEvidenceProjector.ProjectEvidence(findingId, candidate);

            var response = await GenerateAdvisoryAsync(new JsAiAdvisoryRequest(projectedEvidence), ct);
            if (response.Status == AiEnrichmentStatus.Success && response.AdvisoryReport != null)
            {
                reports.Add(response.AdvisoryReport);
            }
        }

        return reports.AsReadOnly();
    }

    private static JsAiAdvisoryReport BuildAdvisoryReport(ProjectedAiEvidence evidence, string modelIdentifier)
    {
        var ruleId = evidence.RuleOrTemplateId.ToLowerInvariant();

        string explanation;
        string threatScenario;
        string falsePositiveNuance;
        string remediation;
        string? suggestedCodeFix;

        if (ruleId.Contains("dom-xss"))
        {
            explanation = $"Untrusted input is passed to a dangerous DOM rendering sink. Static analysis tracked data flow from '{evidence.ParameterName ?? "source"}' to '{evidence.TargetEndpoint}'.";
            threatScenario = "An attacker can craft a malicious URL with payload in the hash or query string. When a victim opens the link, the browser executes the script in the context of their session, potentially allowing session hijacking or credential theft.";
            falsePositiveNuance = "If sanitization libraries (e.g. DOMPurify) are properly configured or if the source is bounded by strict regex matching on the client, the actual exploitability may be mitigated.";
            remediation = "Use 'textContent' or 'innerText' instead of 'innerHTML' when inserting plain text. If HTML is required, sanitize all inputs with DOMPurify before assigning to the DOM.";
            suggestedCodeFix = "// Replace:\n// element.innerHTML = userInput;\n// With:\nelement.textContent = userInput;\n// Or if HTML is required:\nelement.innerHTML = DOMPurify.sanitize(userInput);";
        }
        else if (ruleId.Contains("credential") || ruleId.Contains("secret") || ruleId.Contains("token") || ruleId.Contains("key"))
        {
            explanation = $"Sensitive credential or API token discovered in client-side bundle for endpoint '{evidence.TargetEndpoint}'.";
            threatScenario = "Threat actors can inspect public JavaScript bundles to extract API keys or tokens and access backend cloud resources directly.";
            falsePositiveNuance = "The token may be an intentionally public key (e.g. Stripe publishable key) or a test placeholder. Verify permissions associated with the credential in the provider console.";
            remediation = "Immediately revoke and rotate the exposed token. Move secrets to server-side environment variables and proxy sensitive API requests through your backend.";
            suggestedCodeFix = "// Move secret to server-side .env:\n// BACKEND_API_KEY=your_key_here\n// Proxy request via backend route /api/proxy";
        }
        else if (ruleId.Contains("bola") || ruleId.Contains("idor"))
        {
            explanation = $"Potential Broken Object Level Authorization on endpoint '{evidence.TargetEndpoint}'. Parameter '{evidence.ParameterName ?? "id"}' may lack tenant isolation checks.";
            threatScenario = "An authenticated attacker modifies the object ID in API requests to access other users' private resources without authorization.";
            falsePositiveNuance = "If the endpoint serves public resources or enforces tenancy via invisible session context, the finding may be low risk.";
            remediation = "Enforce object-level ownership checks in backend handlers by validating that the requesting user's tenant ID matches the resource's owner.";
            suggestedCodeFix = "// In backend API handler:\nif (resource.TenantId != currentUser.TenantId) {\n    return Forbid();\n}";
        }
        else
        {
            explanation = $"Security finding '{evidence.FindingTitle}' detected on endpoint '{evidence.TargetEndpoint}'.";
            threatScenario = "Vulnerability could allow unauthorized access or service exposure depending on backend access controls.";
            falsePositiveNuance = "Review whether the endpoint is intended for public consumption and has rate limiting configured.";
            remediation = "Review access controls, input validation schemas, and enforce least privilege.";
            suggestedCodeFix = null;
        }

        return new JsAiAdvisoryReport(
            AdvisoryId: Guid.NewGuid(),
            FindingId: evidence.FindingId,
            RuleOrTemplateId: evidence.RuleOrTemplateId,
            PlainEnglishExplanation: explanation,
            ThreatScenario: threatScenario,
            FalsePositiveNuance: falsePositiveNuance,
            RecommendedRemediation: remediation,
            SuggestedCodeFix: suggestedCodeFix,
            ModelIdentifier: modelIdentifier,
            PromptSchemaVersion: CurrentPromptSchemaVersion,
            GeneratedAtUtc: DateTime.UtcNow,
            IsAdvisoryOnly: true
        );
    }
}
