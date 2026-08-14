using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class JsSecretAnalyzerTests
{
    private readonly JsSecretAnalyzer _analyzer;

    public JsSecretAnalyzerTests()
    {
        _analyzer = new JsSecretAnalyzer(NullLogger<JsSecretAnalyzer>.Instance);
    }

    [Fact]
    public void AnalyzeSecrets_AwsAccessKey_RedactsCleartextAndElevatesContextConfidence()
    {
        var rawKey = "AKIA1234567890ABCDEF";
        var jsCode = $@"
const awsClient = new AWS.S3({{
    accessKeyId: '{rawKey}',
    region: 'us-east-1'
}});";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/aws-bundle.js",
            CanonicalUrl: "https://app.example.com/aws-bundle.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_aws",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var result = _analyzer.AnalyzeSecrets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Single(result.FindingCandidates);
        var finding = result.FindingCandidates[0];

        Assert.Equal(FindingType.UnvalidatedCredentialExposed, finding.FindingType);
        Assert.Equal("aws-access-key", finding.RuleOrTemplateId);
        Assert.Contains("AKIA...CDEF", finding.Description);
        Assert.DoesNotContain(rawKey, finding.Description);
        Assert.DoesNotContain(rawKey, finding.RawEvidenceJson);

        using var doc = JsonDocument.Parse(finding.RawEvidenceJson!);
        var root = doc.RootElement;
        Assert.Equal("AKIA...CDEF", root.GetProperty("redacted_value").GetString());
        Assert.Equal("Medium", root.GetProperty("confidence").GetString());
        Assert.Equal("ConfigObject", root.GetProperty("usage_context").GetString());
    }

    [Fact]
    public void AnalyzeSecrets_KnownPlaceholderKey_DegradedToInformational()
    {
        var jsCode = "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/mock.js",
            CanonicalUrl: "https://app.example.com/mock.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_mock",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var result = _analyzer.AnalyzeSecrets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Single(result.FindingCandidates);
        var finding = result.FindingCandidates[0];

        using var doc = JsonDocument.Parse(finding.RawEvidenceJson!);
        Assert.Equal("Low", doc.RootElement.GetProperty("confidence").GetString());
        Assert.Equal("TestOrExample", doc.RootElement.GetProperty("usage_context").GetString());
    }

    [Fact]
    public void AnalyzeSecrets_CrossChunkDeduplication_AggregatesAcrossMultipleAssets()
    {
        var rawKey = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        var js1 = $"const token = '{rawKey}';";
        var js2 = $"const auth = {{ Authorization: 'Bearer {rawKey}' }};";
        var js3 = $"export const GH = '{rawKey}';";

        var asset1 = new JavaScriptAsset(Guid.NewGuid(), Guid.NewGuid(), "https://app.example.com/chunk-1.js", "https://app.example.com/chunk-1.js", JsAssetType.JavaScript, "sha1", js1.Length, 1);
        var asset2 = new JavaScriptAsset(Guid.NewGuid(), Guid.NewGuid(), "https://app.example.com/chunk-2.js", "https://app.example.com/chunk-2.js", JsAssetType.JavaScript, "sha2", js2.Length, 1);
        var asset3 = new JavaScriptAsset(Guid.NewGuid(), Guid.NewGuid(), "https://app.example.com/app.bundle.js", "https://app.example.com/app.bundle.js", JsAssetType.JavaScript, "sha3", js3.Length, 0);

        var result = _analyzer.AnalyzeSecrets(Guid.NewGuid(), new[]
        {
            (asset1, js1),
            (asset2, js2),
            (asset3, js3)
        });

        // 3 occurrences in 3 assets aggregated into 1 deduplicated candidate
        Assert.Equal(3, result.TotalSecretsDetected);
        Assert.Equal(1, result.DeduplicatedSecretsCount);
        Assert.Single(result.FindingCandidates);

        var finding = result.FindingCandidates[0];
        Assert.Equal("github-token", finding.RuleOrTemplateId);

        using var doc = JsonDocument.Parse(finding.RawEvidenceJson!);
        var root = doc.RootElement;
        Assert.Equal(3, root.GetProperty("occurrences_count").GetInt32());
        var assetsArray = root.GetProperty("discovered_in_assets").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("https://app.example.com/chunk-1.js", assetsArray);
        Assert.Contains("https://app.example.com/chunk-2.js", assetsArray);
        Assert.Contains("https://app.example.com/app.bundle.js", assetsArray);
    }

    [Fact]
    public void AnalyzeSecrets_InternalHostname_EmittedAsInfrastructureFactNotCredential()
    {
        var jsCode = @"
const INTERNAL_AUTH = 'https://auth.corp.internal/oauth/v2/token';
const STAGING_DB = 'redis://cache.staging.local:6379';";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/config.js",
            CanonicalUrl: "https://app.example.com/config.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_cfg",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var result = _analyzer.AnalyzeSecrets(asset.ScanJobId, new[] { (asset, jsCode) });

        // Internal hostnames are separated into DiscoveredInternalHosts
        Assert.Contains("auth.corp.internal", result.DiscoveredInternalHosts);
        Assert.Contains("cache.staging.local", result.DiscoveredInternalHosts);

        // DiscoveredInternalHosts is NOT emitted as an UnvalidatedCredentialExposed finding
        Assert.DoesNotContain(result.FindingCandidates, f => f.RuleOrTemplateId == "internal-hostname");

        // Database URI is emitted as database-connection-uri finding
        Assert.Contains(result.FindingCandidates, f => f.RuleOrTemplateId == "database-connection-uri");
    }

    [Fact]
    public void AnalyzeSecrets_SourceMapAssets_UnpacksOriginalSourceProvenance()
    {
        var rawKey = "sk_live_1234567890abcdef12345678";
        var sourceMapJson = $@"{{
  ""version"": 3,
  ""file"": ""bundle.min.js"",
  ""sources"": [""src/config/stripe.ts""],
  ""sourcesContent"": [""export const STRIPE_KEY = '{rawKey}';""]
}}";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/bundle.min.js.map",
            CanonicalUrl: "https://app.example.com/bundle.min.js.map",
            AssetType: JsAssetType.JavaScriptMap,
            ContentSha256: "sha_map",
            ContentLengthBytes: sourceMapJson.Length,
            Depth: 1
        );

        var result = _analyzer.AnalyzeSecrets(asset.ScanJobId, new[] { (asset, sourceMapJson) });

        Assert.Single(result.FindingCandidates);
        var finding = result.FindingCandidates[0];

        using var doc = JsonDocument.Parse(finding.RawEvidenceJson!);
        var root = doc.RootElement;
        Assert.Equal("SourceMapOriginalSource", root.GetProperty("provenance").GetString());
        var sourceFiles = root.GetProperty("original_source_files").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("src/config/stripe.ts", sourceFiles);
    }
}
