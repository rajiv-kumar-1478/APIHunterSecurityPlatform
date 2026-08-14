using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.JavaScript.Contracts;

/// <summary>
/// Authoritative unified aggregation contract combining AST API routes, secret intelligence,
/// and client-side data-flow facts across all discovered JavaScript assets.
/// </summary>
public sealed record UnifiedJsAnalysisResult(
    Guid ScanJobId,
    JsAttackSurfaceGraph AttackSurface,
    JsSecretAnalysisResult Secrets,
    JsDataFlowAnalysisResult DataFlows,
    IReadOnlyList<FindingCandidate> CombinedFindingCandidates,
    ScannerCoverage Coverage,
    DateTime AnalyzedAtUtc
);
