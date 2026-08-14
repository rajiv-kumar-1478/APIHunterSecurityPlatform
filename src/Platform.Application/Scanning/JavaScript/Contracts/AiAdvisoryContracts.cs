using System;
using System.Collections.Generic;

namespace Platform.Application.Scanning.JavaScript.Contracts;

public enum AiEnrichmentStatus
{
    Success = 1,
    SkippedDisabled = 2,
    FailedTimeout = 3,
    FailedError = 4
}

/// <summary>
/// Safe, sanitized evidence projection passed across the LLM boundary.
/// Guaranteed free of cleartext secrets, cookies, session headers, and unbounded snippets.
/// </summary>
public sealed record ProjectedAiEvidence(
    Guid FindingId,
    string RuleOrTemplateId,
    string FindingTitle,
    string TargetEndpoint,
    string? HttpMethod,
    string? ParameterName,
    string SanitizedCodeSnippet,
    IReadOnlyDictionary<string, string> SanitizedContextDetails,
    int PromptTokenEstimate
);

/// <summary>
/// Strongly-typed request to the AI Advisory Enrichment Service.
/// </summary>
public sealed record JsAiAdvisoryRequest(
    ProjectedAiEvidence Evidence,
    string? PreferredModel = null,
    TimeSpan? Timeout = null
);

/// <summary>
/// Authoritative non-authoritative AI advisory report attached to a SecurityFinding.
/// </summary>
public sealed record JsAiAdvisoryReport(
    Guid AdvisoryId,
    Guid FindingId,
    string RuleOrTemplateId,
    string PlainEnglishExplanation,
    string ThreatScenario,
    string FalsePositiveNuance,
    string RecommendedRemediation,
    string? SuggestedCodeFix,
    string ModelIdentifier,
    string PromptSchemaVersion,
    DateTime GeneratedAtUtc,
    bool IsAdvisoryOnly = true
);

/// <summary>
/// Execution response from the AI Advisory Service with fail-open status.
/// </summary>
public sealed record JsAiEnrichmentResponse(
    AiEnrichmentStatus Status,
    JsAiAdvisoryReport? AdvisoryReport,
    string? ErrorMessage = null,
    long DurationMs = 0
);
