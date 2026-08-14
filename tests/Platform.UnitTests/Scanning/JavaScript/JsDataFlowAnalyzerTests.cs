using System;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class JsDataFlowAnalyzerTests
{
    private readonly JsDataFlowAnalyzer _analyzer;

    public JsDataFlowAnalyzerTests()
    {
        _analyzer = new JsDataFlowAnalyzer(NullLogger<JsDataFlowAnalyzer>.Instance);
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
    public void AnalyzeDataFlow_DirectLocationHashToInnerHtml_EmitsMediumConfidenceFlow()
    {
        var code = @"
            const hash = location.hash;
            document.getElementById('output').innerHTML = hash;
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Single(result.DetectedFlows);
        var flow = result.DetectedFlows[0];

        Assert.Equal(TaintSourceKind.LocationHash, flow.SourceKind);
        Assert.Equal(TaintSinkKind.InnerHtml, flow.SinkKind);
        Assert.Equal(SanitizerKind.None, flow.DetectedSanitizer);
        Assert.Equal(FindingConfidence.Medium, flow.Confidence);

        Assert.Single(result.FindingCandidates);
        var candidate = result.FindingCandidates[0];
        Assert.Equal("dom-xss-potential", candidate.RuleOrTemplateId);
        Assert.Equal("medium", candidate.RawSeverity);
    }

    [Fact]
    public void AnalyzeDataFlow_SanitizedWithDOMPurify_EmitsLowConfidenceFlow()
    {
        var code = @"
            const input = location.search;
            const clean = DOMPurify.sanitize(input);
            document.body.innerHTML = clean;
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Single(result.DetectedFlows);
        var flow = result.DetectedFlows[0];

        Assert.Equal(TaintSourceKind.LocationSearch, flow.SourceKind);
        Assert.Equal(TaintSinkKind.InnerHtml, flow.SinkKind);
        Assert.Equal(SanitizerKind.DomPurify, flow.DetectedSanitizer);
        Assert.False(flow.IsSanitizerVerified); // Unverified effectiveness
        Assert.Equal(FindingConfidence.Low, flow.Confidence);

        Assert.Single(result.FindingCandidates);
        Assert.Equal("low", result.FindingCandidates[0].RawSeverity);
    }

    [Fact]
    public void AnalyzeDataFlow_EncodeUriComponent_EmitsLowConfidenceFlow()
    {
        var code = @"
            const raw = location.hash;
            const encoded = encodeURIComponent(raw);
            document.getElementById('content').innerHTML = encoded;
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Single(result.DetectedFlows);
        var flow = result.DetectedFlows[0];

        Assert.Equal(SanitizerKind.EncodeUriComponent, flow.DetectedSanitizer);
        Assert.Equal(FindingConfidence.Low, flow.Confidence);
    }

    [Fact]
    public void AnalyzeDataFlow_PostMessageToEval_EmitsMediumConfidenceFlow()
    {
        var code = @"
            window.addEventListener('message', (event) => {
                const cmd = event.data;
                eval(cmd);
            });
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Single(result.DetectedFlows);
        var flow = result.DetectedFlows[0];

        Assert.Equal(TaintSourceKind.PostMessageData, flow.SourceKind);
        Assert.Equal(TaintSinkKind.Eval, flow.SinkKind);
        Assert.Equal(FindingConfidence.Medium, flow.Confidence);
    }

    [Fact]
    public void AnalyzeDataFlow_TemplateLiteralInterpolationToDocumentWrite_PropagatesTaint()
    {
        var code = @"
            const param = location.hash;
            const markup = `<div><h1>${param}</h1></div>`;
            document.write(markup);
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Single(result.DetectedFlows);
        var flow = result.DetectedFlows[0];

        Assert.Equal(TaintSourceKind.LocationHash, flow.SourceKind);
        Assert.Equal(TaintSinkKind.DocumentWrite, flow.SinkKind);
        Assert.Contains("TemplateLiteralInterpolation", flow.TransformationHops);
    }

    [Fact]
    public void AnalyzeDataFlow_SafeConstantString_DoesNotEmitFlow()
    {
        var code = @"
            const title = '<h1>Welcome</h1>';
            document.getElementById('header').innerHTML = title;
            document.write('<p>Footer</p>');
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Empty(result.DetectedFlows);
        Assert.Empty(result.FindingCandidates);
    }

    [Fact]
    public void AnalyzeDataFlow_ExceedingMaxPropagationHops_DoesNotEmitCandidate()
    {
        // 7 hops > Max 5 hops
        var code = @"
            let a = location.hash;
            let b = a;
            let c = b;
            let d = c;
            let e = d;
            let f = e;
            let g = f;
            document.getElementById('test').innerHTML = g;
        ";

        var asset = CreateTestAsset("https://example.com/app.js", code);
        var result = _analyzer.AnalyzeDataFlow(Guid.NewGuid(), new[] { (asset, code) });

        Assert.Empty(result.DetectedFlows);
        Assert.Empty(result.FindingCandidates);
    }
}
