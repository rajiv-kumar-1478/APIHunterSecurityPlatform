using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative unified JavaScript analysis engine coordinating AST API discovery,
/// secret intelligence, and client-side data-flow DOM-XSS analysis.
/// </summary>
public sealed class UnifiedJsAnalyzer : IUnifiedJsAnalyzer
{
    private readonly IJsAstAnalyzer _astAnalyzer;
    private readonly IJsSecretAnalyzer _secretAnalyzer;
    private readonly IJsDataFlowAnalyzer _dataFlowAnalyzer;
    private readonly ILogger<UnifiedJsAnalyzer> _logger;

    public UnifiedJsAnalyzer(
        IJsAstAnalyzer astAnalyzer,
        IJsSecretAnalyzer secretAnalyzer,
        IJsDataFlowAnalyzer dataFlowAnalyzer,
        ILogger<UnifiedJsAnalyzer> logger)
    {
        _astAnalyzer = astAnalyzer ?? throw new ArgumentNullException(nameof(astAnalyzer));
        _secretAnalyzer = secretAnalyzer ?? throw new ArgumentNullException(nameof(secretAnalyzer));
        _dataFlowAnalyzer = dataFlowAnalyzer ?? throw new ArgumentNullException(nameof(dataFlowAnalyzer));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public UnifiedJsAnalysisResult Analyze(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string Content)> assets)
    {
        assets ??= Array.Empty<(JavaScriptAsset, string)>();

        _logger.LogInformation("Starting unified JS analysis for scan job '{JobId}' across {Count} assets.",
            scanJobId, assets.Count);

        // 1. AST API Route & Attack Surface Analysis
        var attackSurface = _astAnalyzer.AnalyzeAssets(scanJobId, assets);

        // 2. Secret & Sensitive-Value Intelligence Analysis
        var secrets = _secretAnalyzer.AnalyzeSecrets(scanJobId, assets);

        // 3. Client-Side Data-Flow & DOM-XSS Intelligence Analysis
        var dataFlows = _dataFlowAnalyzer.AnalyzeDataFlow(scanJobId, assets);

        // 4. Combine Finding Candidates
        var combinedCandidates = new List<FindingCandidate>();
        combinedCandidates.AddRange(secrets.FindingCandidates);
        combinedCandidates.AddRange(dataFlows.FindingCandidates);

        // 5. Build Aggregated Coverage Metrics
        var totalParams = attackSurface.Endpoints.Sum(e => e.Parameters.Count);
        var coverage = new ScannerCoverage(
            EndpointsDiscovered: attackSurface.TotalRoutesDiscovered,
            ParametersExtracted: totalParams,
            AssetsProbed: assets.Count,
            JavaScriptFilesDiscovered: assets.Count,
            CoverageTruncated: false,
            CoverageTruncationReason: null,
            MalformedRecordCount: 0,
            OutputTruncated: false,
            CoverageDetails: new Dictionary<string, object>
            {
                ["DiscoveredInternalHostsCount"] = secrets.DiscoveredInternalHosts.Count,
                ["DomXssFlowsCount"] = dataFlows.DetectedFlows.Count,
                ["BoundedAnalysisExhaustions"] = dataFlows.BoundedAnalysisExhaustionCount
            }
        );

        _logger.LogInformation("Completed unified JS analysis for scan job '{JobId}': {Apis} APIs, {Secrets} Secrets, {Flows} DOM-XSS flows.",
            scanJobId, attackSurface.TotalRoutesDiscovered, secrets.FindingCandidates.Count, dataFlows.DetectedFlows.Count);

        return new UnifiedJsAnalysisResult(
            ScanJobId: scanJobId,
            AttackSurface: attackSurface,
            Secrets: secrets,
            DataFlows: dataFlows,
            CombinedFindingCandidates: combinedCandidates.AsReadOnly(),
            Coverage: coverage,
            AnalyzedAtUtc: DateTime.UtcNow
        );
    }
}
