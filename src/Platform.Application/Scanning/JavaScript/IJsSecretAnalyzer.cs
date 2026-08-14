using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative JavaScript secret and sensitive-value intelligence engine.
/// Combines deterministic pattern matching with AST usage correlation, entropy scoring,
/// cross-chunk deduplication, and strict cleartext redaction.
/// </summary>
public interface IJsSecretAnalyzer
{
    /// <summary>
    /// Analyzes JavaScript assets for sensitive credentials and internal infrastructure.
    /// Emits sanitized FindingCandidate records for credentials and infrastructure facts for coverage.
    /// </summary>
    JsSecretAnalysisResult AnalyzeSecrets(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string JsCode)> assets);
}
