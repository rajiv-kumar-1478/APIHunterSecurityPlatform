using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative ECMAScript AST analyzer for structural API, GraphQL, and WebSocket discovery.
/// Performs AST parsing, bounded constant propagation, and endpoint/parameter extraction.
/// </summary>
public interface IJsAstAnalyzer
{
    /// <summary>
    /// Parses JavaScript asset code into ASTs and generates the hierarchical Attack Surface Graph.
    /// </summary>
    JsAttackSurfaceGraph AnalyzeAssets(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string JsCode)> assets);

    /// <summary>
    /// Computes incremental attack-surface differences (new, changed, unchanged, removed endpoints) between two graphs.
    /// </summary>
    JsAttackSurfaceDiff ComputeAttackSurfaceDiff(
        Guid currentScanJobId,
        Guid? baselineScanJobId,
        JsAttackSurfaceGraph currentGraph,
        JsAttackSurfaceGraph baselineGraph);
}
