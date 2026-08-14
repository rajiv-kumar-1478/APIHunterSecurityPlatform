using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class JsMinerAdapterTests
{
    private readonly JsMinerAdapter _adapter;
    private readonly JsMinerOutputParser _parser;

    public JsMinerAdapterTests()
    {
        _parser = new JsMinerOutputParser(NullLogger<JsMinerOutputParser>.Instance);
        _adapter = new JsMinerAdapter(_parser);
    }

    [Fact]
    public void Manifest_IsValidAccordingToContract()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal("jsminer", _adapter.Manifest.ToolKey);
        Assert.Equal("1.2.0", _adapter.Manifest.Version);
        Assert.StartsWith("sha256:", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Deep, _adapter.Manifest.SupportedProfiles);
    }

    [Theory]
    [InlineData(SecurityScanProfileType.Standard, "3")]
    [InlineData(SecurityScanProfileType.Deep, "5")]
    public void PrepareExecution_BuildsAccuratePlan(SecurityScanProfileType profile, string expectedDepth)
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: profile,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("jsminer", plan.ToolKey);
        Assert.Contains("-u", plan.CommandLineArguments);
        Assert.Contains("https://app.example.com", plan.CommandLineArguments);
        Assert.Contains("-depth", plan.CommandLineArguments);
        Assert.Contains(expectedDepth, plan.CommandLineArguments);
        Assert.Contains("-extract-endpoints", plan.CommandLineArguments);
        Assert.Contains("-extract-secrets", plan.CommandLineArguments);
        Assert.Contains("-detect-domxss", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutput_HappyPathGoldenFixture_ExtractsCandidatesAndCoverage()
    {
        var goldenOutput = string.Join("\n", new[]
        {
            "{\"type\":\"js_file\",\"url\":\"https://app.example.com/assets/app.bundle.js\"}",
            "{\"type\":\"endpoint\",\"method\":\"POST\",\"url\":\"/api/v2/auth/login\",\"sourceJsUrl\":\"https://app.example.com/assets/app.bundle.js\",\"params\":[\"username\",\"password\",\"remember_me\"]}",
            "{\"type\":\"endpoint\",\"method\":\"GET\",\"url\":\"/api/v2/users/export\",\"sourceJsUrl\":\"https://app.example.com/assets/app.bundle.js\",\"params\":[\"format\",\"tenant_id\"]}",
            "{\"type\":\"secret\",\"patternId\":\"aws-access-key\",\"secretType\":\"AWS Access Key\",\"sourceJsUrl\":\"https://app.example.com/assets/app.bundle.js\",\"line\":142,\"column\":18,\"snippet\":\"const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\"}",
            "{\"type\":\"dom_xss\",\"source\":\"location.hash\",\"sink\":\"element.innerHTML\",\"sourceJsUrl\":\"https://app.example.com/assets/app.bundle.js\",\"line\":204,\"column\":5,\"snippet\":\"document.getElementById('content').innerHTML = location.hash.substring(1);\"}"
        });

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("jsminer", "1.2.0", 0, goldenOutput, string.Empty, Encoding.UTF8.GetByteCount(goldenOutput), 150);
        var parsed = await _adapter.ParseOutputAsync(context, raw);

        Assert.NotNull(parsed.Coverage);
        Assert.Equal(2, parsed.FindingCandidates.Count);

        // Verify unvalidated secret candidate
        var secretCandidate = parsed.FindingCandidates.FirstOrDefault(c => c.RuleOrTemplateId == "aws-access-key");
        Assert.NotNull(secretCandidate);
        Assert.Equal(FindingType.UnvalidatedCredentialExposed, secretCandidate.FindingType);
        Assert.Equal("medium", secretCandidate.RawSeverity);
        Assert.Equal("jsminer", secretCandidate.ToolKey);
        Assert.Contains("AKIAIOSFODNN7EXAMPLE", secretCandidate.RawEvidenceJson);

        // Verify DOM XSS potential dataflow candidate
        var domCandidate = parsed.FindingCandidates.FirstOrDefault(c => c.RuleOrTemplateId == "dom-xss-potential");
        Assert.NotNull(domCandidate);
        Assert.Equal("low", domCandidate.RawSeverity);
        Assert.Equal("location.hash", domCandidate.ParameterName);
        Assert.Contains("innerHTML", domCandidate.RawEvidenceJson);

        // Verify Coverage
        Assert.Equal(2, parsed.Coverage.EndpointsDiscovered);
        Assert.Equal(5, parsed.Coverage.ParametersExtracted);
        Assert.Equal(1, parsed.Coverage.JavaScriptFilesDiscovered);
        Assert.Equal(0, parsed.Coverage.MalformedRecordCount);
        Assert.False(parsed.Coverage.CoverageTruncated);
    }

    [Fact]
    public async Task ParseOutput_AdversarialMalformedLines_PreservesSurroundingValidRecords()
    {
        var mixedOutput = string.Join("\n", new[]
        {
            "{\"type\":\"endpoint\",\"method\":\"GET\",\"url\":\"/api/v1/health\",\"sourceJsUrl\":\"https://app.example.com/bundle.js\"}",
            "{ THIS_IS_NOT_VALID_JSON !!! }",
            "{\"type\":\"secret\",\"patternId\":\"jwt-token\",\"secretType\":\"Bearer Token\",\"sourceJsUrl\":\"https://app.example.com/bundle.js\",\"line\":50,\"column\":10,\"snippet\":\"const token = 'ey...';\"}",
            "NOT JSON AT ALL",
            "{\"type\":\"endpoint\",\"method\":\"GET\",\"url\":\"/api/v1/status\",\"sourceJsUrl\":\"https://app.example.com/bundle.js\"}"
        });

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("jsminer", "1.2.0", 0, mixedOutput, string.Empty, Encoding.UTF8.GetByteCount(mixedOutput), 150);
        var parsed = await _adapter.ParseOutputAsync(context, raw);

        Assert.NotNull(parsed.Coverage);
        // 1 secret candidate successfully parsed despite 2 malformed lines
        Assert.Single(parsed.FindingCandidates);
        Assert.Equal("jwt-token", parsed.FindingCandidates[0].RuleOrTemplateId);

        // 2 endpoints successfully parsed
        Assert.Equal(2, parsed.Coverage.EndpointsDiscovered);
        Assert.Equal(2, parsed.Coverage.MalformedRecordCount);
        Assert.False(parsed.Coverage.CoverageTruncated);
    }

    [Fact]
    public async Task ParseOutput_AdversarialDuplicates_DeduplicatesCorrectly()
    {
        var duplicateOutput = string.Join("\n", new[]
        {
            "{\"type\":\"endpoint\",\"method\":\"GET\",\"url\":\"/api/v1/users\",\"params\":[\"id\",\"id\"]}",
            "{\"type\":\"endpoint\",\"method\":\"GET\",\"url\":\"/api/v1/users\",\"params\":[\"id\"]}",
            "{\"type\":\"secret\",\"patternId\":\"aws-key\",\"secretType\":\"AWS\",\"sourceJsUrl\":\"https://app.example.com/bundle.js\",\"line\":10,\"column\":5,\"snippet\":\"test\"}",
            "{\"type\":\"secret\",\"patternId\":\"aws-key\",\"secretType\":\"AWS\",\"sourceJsUrl\":\"https://app.example.com/bundle.js\",\"line\":10,\"column\":5,\"snippet\":\"test\"}"
        });

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("jsminer", "1.2.0", 0, duplicateOutput, string.Empty, Encoding.UTF8.GetByteCount(duplicateOutput), 150);
        var parsed = await _adapter.ParseOutputAsync(context, raw);

        Assert.NotNull(parsed.Coverage);
        Assert.Single(parsed.FindingCandidates);
        Assert.Equal(1, parsed.Coverage.EndpointsDiscovered);
        Assert.Equal(1, parsed.Coverage.ParametersExtracted);
    }

    [Fact]
    public async Task ParseOutput_OversizedPayload_FailsClosedWithTelemetry()
    {
        // 10 MiB + 1 byte
        var oversizedBuilder = new StringBuilder();
        oversizedBuilder.Append("{\"type\":\"endpoint\",\"url\":\"/api\"}\n");
        oversizedBuilder.Append(new string('A', 10 * 1024 * 1024 + 10));
        var text = oversizedBuilder.ToString();

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("jsminer", "1.2.0", 0, text, string.Empty, Encoding.UTF8.GetByteCount(text), 150);
        var parsed = await _adapter.ParseOutputAsync(context, raw);

        Assert.NotNull(parsed.Coverage);
        Assert.Empty(parsed.FindingCandidates);
        Assert.True(parsed.Coverage.CoverageTruncated);
        Assert.True(parsed.Coverage.OutputTruncated);
        Assert.Equal("MaxRawOutputBytesExceeded", parsed.Coverage.CoverageTruncationReason);
    }

    [Fact]
    public async Task ParseOutput_LongCodeSnippet_TruncatedToMaxSnippetLength()
    {
        var longSnippet = new string('x', 1000);
        var json = $"{{\"type\":\"secret\",\"patternId\":\"key\",\"secretType\":\"Token\",\"sourceJsUrl\":\"https://app.example.com/app.js\",\"line\":1,\"column\":1,\"snippet\":\"{longSnippet}\"}}";

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("jsminer", "1.2.0", 0, json, string.Empty, Encoding.UTF8.GetByteCount(json), 150);
        var parsed = await _adapter.ParseOutputAsync(context, raw);

        Assert.Single(parsed.FindingCandidates);
        Assert.Contains("xxx...", parsed.FindingCandidates[0].RawEvidenceJson);
    }
}
