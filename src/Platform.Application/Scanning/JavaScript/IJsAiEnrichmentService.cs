using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative non-authoritative AI Advisory Enrichment service providing human-readable explanations,
/// threat scenarios, false-positive nuances, and code-level remediation suggestions.
/// </summary>
public interface IJsAiEnrichmentService
{
    /// <summary>
    /// Generates structured AI advisory guidance for a single finding request.
    /// </summary>
    Task<JsAiEnrichmentResponse> GenerateAdvisoryAsync(
        JsAiAdvisoryRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// Asynchronously enriches a collection of finding candidates with advisory reports.
    /// Failures in advisory generation never impact finding creation or scan status.
    /// </summary>
    Task<IReadOnlyList<JsAiAdvisoryReport>> EnrichFindingCandidatesAsync(
        IReadOnlyList<FindingCandidate> candidates,
        CancellationToken ct = default);
}
