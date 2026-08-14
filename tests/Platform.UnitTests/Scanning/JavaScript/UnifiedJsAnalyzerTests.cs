using System;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class UnifiedJsAnalyzerTests
{
    private readonly UnifiedJsAnalyzer _unifiedAnalyzer;

    public UnifiedJsAnalyzerTests()
    {
        var astAnalyzer = new JsAstAnalyzer(NullLogger<JsAstAnalyzer>.Instance);
        var secretAnalyzer = new JsSecretAnalyzer(NullLogger<JsSecretAnalyzer>.Instance);
        var dataFlowAnalyzer = new JsDataFlowAnalyzer(NullLogger<JsDataFlowAnalyzer>.Instance);

        _unifiedAnalyzer = new UnifiedJsAnalyzer(
            astAnalyzer,
            secretAnalyzer,
            dataFlowAnalyzer,
            NullLogger<UnifiedJsAnalyzer>.Instance
        );
    }

    private static JavaScriptAsset CreateTestAsset(string url, string code)
    {
        return new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: url,
            CanonicalUrl: url,
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_" + Guid.NewGuid().ToString("N")[..8],
            ContentLengthBytes: code.Length,
            Depth: 0
        );
    }

    [Fact]
    public void Analyze_MultiFacetBundle_AggregatesApisSecretsAndDomXss()
    {
        var scanJobId = Guid.NewGuid();
        var code = @"
            // 1. API Route
            fetch('/api/v2/users/' + id);

            // 2. Secret
            const stripeKey = 'pk_live_51Abcd123456789012345678901234567890';

            // 3. DOM-XSS
            const hash = location.hash;
            document.getElementById('profile').innerHTML = hash;
        ";

        var asset = CreateTestAsset("https://example.com/bundle.js", code);
        var result = _unifiedAnalyzer.Analyze(scanJobId, new[] { (asset, code) });

        Assert.Equal(scanJobId, result.ScanJobId);

        // 1. AST Routes
        Assert.Single(result.AttackSurface.Endpoints);
        Assert.Equal("/api/v2/users/{id}", result.AttackSurface.Endpoints[0].RoutePath);

        // 2. Secrets
        Assert.NotEmpty(result.Secrets.FindingCandidates);

        // 3. Data Flows
        Assert.Single(result.DataFlows.DetectedFlows);
        Assert.Equal(TaintSourceKind.LocationHash, result.DataFlows.DetectedFlows[0].SourceKind);

        // 4. Combined Candidates (1 Secret + 1 DOM-XSS = 2)
        Assert.Equal(2, result.CombinedFindingCandidates.Count);

        // 5. Coverage
        Assert.Equal(1, result.Coverage.EndpointsDiscovered);
        Assert.Equal(1, result.Coverage.JavaScriptFilesDiscovered);
    }
}
