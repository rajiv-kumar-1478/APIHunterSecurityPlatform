using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative AST data-flow analyzer tracking untrusted sources to dangerous DOM sinks.
/// </summary>
public interface IJsDataFlowAnalyzer
{
    /// <summary>
    /// Performs bounded AST taint propagation across JavaScript assets to identify potential DOM-XSS flows.
    /// </summary>
    JsDataFlowAnalysisResult AnalyzeDataFlow(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string Content)> assets);
}
