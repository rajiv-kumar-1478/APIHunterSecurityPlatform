using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanToolManifestValidatorTests
{
    private static ScanToolManifest CreateValidManifest(
        string toolKey = "httpx",
        string version = "1.6.0",
        string digest = "sha256:52d58be716e8fe2a592da2a3a3652985d6c71c9b68a6f3dc8e4b789ad7e2c91b")
    {
        return new ScanToolManifest(
            ToolKey: toolKey,
            Version: version,
            Description: "HTTP probing and service discovery engine",
            ContainerImageRepository: "ghcr.io/apihunter-security/httpx",
            ContainerImageReference: $"ghcr.io/apihunter-security/httpx:{version}",
            ContainerImageDigest: digest,
            SupportedProfiles: new HashSet<SecurityScanProfileType> { SecurityScanProfileType.Recon, SecurityScanProfileType.Standard },
            Capabilities: new HashSet<string> { "http.probe", "tls.inspect" },
            DiscoveredAssetTypes: new[] { "endpoint", "tls_certificate" },
            ParserVersion: "1.0",
            ManifestVersion: "1.0"
        );
    }

    [Fact]
    public void Validate_ValidManifest_ReturnsSuccess()
    {
        var manifest = CreateValidManifest();
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_EmptyStringDigest_FailsValidation()
    {
        var manifest = CreateValidManifest(digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("empty string"));
    }

    [Fact]
    public void Validate_AllZeroPlaceholderDigest_FailsValidation()
    {
        var manifest = CreateValidManifest(digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000");
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("trivial placeholder"));
    }

    [Theory]
    [InlineData("1.0.0")]
    [InlineData("v2.4.1")]
    [InlineData("2026.08")]
    [InlineData("1.0.0-beta.1")]
    [InlineData("3.1.0+build.2026")]
    public void Validate_SupportedVersionFormats_PassesValidation(string validVersion)
    {
        var manifest = CreateValidManifest(version: validVersion);
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("INVALID VERSION WITH SPACES")]
    [InlineData("---")]
    [InlineData("")]
    public void Validate_InvalidVersionFormats_FailsValidation(string invalidVersion)
    {
        var manifest = CreateValidManifest(version: invalidVersion);
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Version"));
    }

    [Theory]
    [InlineData("Tool_Key_Uppercase")]
    [InlineData("tool key with spaces")]
    [InlineData("tool@key")]
    public void Validate_InvalidToolKey_FailsValidation(string invalidKey)
    {
        var manifest = CreateValidManifest(toolKey: invalidKey);
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("ToolKey"));
    }

    [Theory]
    [InlineData("md5:12345")]
    [InlineData("sha256:short")]
    [InlineData("not-a-digest")]
    public void Validate_InvalidDigest_FailsValidation(string invalidDigest)
    {
        var manifest = CreateValidManifest(digest: invalidDigest);
        var result = ScanToolManifestValidator.Validate(manifest);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("ContainerImageDigest"));
    }

    [Fact]
    public void Registry_DuplicateKey_ThrowsInvalidOperationException()
    {
        var adapter1 = new MockScanAdapter(CreateValidManifest("httpx", "1.0.0"));
        var adapter2 = new MockScanAdapter(CreateValidManifest("httpx", "2.0.0"));

        Assert.Throws<InvalidOperationException>(() => new ScanToolRegistry(new[] { adapter1, adapter2 }));
    }

    [Fact]
    public void Registry_GetAdaptersForProfile_ReturnsMatchingAdapters()
    {
        var httpxManifest = CreateValidManifest("httpx");
        var nucleiManifest = new ScanToolManifest(
            ToolKey: "nuclei",
            Version: "3.2.0",
            Description: "Vulnerability scanner",
            ContainerImageRepository: "ghcr.io/apihunter-security/nuclei",
            ContainerImageReference: "ghcr.io/apihunter-security/nuclei:v3.2.0",
            ContainerImageDigest: "sha256:1a85e13b8279930f796de14187063d80b721e7d8001fb1e204c35e39d5628bbf",
            SupportedProfiles: new HashSet<SecurityScanProfileType> { SecurityScanProfileType.Standard, SecurityScanProfileType.Deep },
            Capabilities: new HashSet<string> { "cve.detect" },
            DiscoveredAssetTypes: new[] { "vulnerability" },
            ParserVersion: "1.0",
            ManifestVersion: "1.0"
        );

        var registry = new ScanToolRegistry(new[]
        {
            new MockScanAdapter(httpxManifest),
            new MockScanAdapter(nucleiManifest)
        });

        var reconAdapters = registry.GetAdaptersForProfile(SecurityScanProfileType.Recon);
        Assert.Single(reconAdapters);
        Assert.Equal("httpx", reconAdapters[0].Manifest.ToolKey);

        var deepAdapters = registry.GetAdaptersForProfile(SecurityScanProfileType.Deep);
        Assert.Single(deepAdapters);
        Assert.Equal("nuclei", deepAdapters[0].Manifest.ToolKey);
    }

    private sealed class MockScanAdapter : IScanToolAdapter
    {
        public ScanToolManifest Manifest { get; }

        public MockScanAdapter(ScanToolManifest manifest)
        {
            Manifest = manifest;
        }

        public ToolExecutionPlan PrepareExecution(ScanExecutionContext context) =>
            new(Manifest.ToolKey, Manifest.Version, Array.Empty<string>(), new Dictionary<string, string>());

        public System.Threading.Tasks.Task<ToolParsedOutputResult> ParseOutputAsync(
            ScanExecutionContext context,
            ToolExecutionRawOutput rawOutput,
            System.Threading.CancellationToken ct = default) =>
            System.Threading.Tasks.Task.FromResult(new ToolParsedOutputResult(Manifest.ToolKey, Manifest.Version, Array.Empty<FindingCandidate>(), null));
    }
}
