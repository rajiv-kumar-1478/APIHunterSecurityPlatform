using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative unified JavaScript analysis engine coordinating AST API discovery,
/// secret intelligence, and client-side data-flow DOM-XSS analysis.
/// </summary>
public interface IUnifiedJsAnalyzer
{
    /// <summary>
    /// Executes all deterministic JavaScript intelligence analyzers and aggregates findings and coverage facts.
    /// </summary>
    UnifiedJsAnalysisResult Analyze(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string Content)> assets);
}
