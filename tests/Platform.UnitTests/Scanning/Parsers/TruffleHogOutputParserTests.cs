using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Parsers;

public class TruffleHogOutputParserTests
{
    private readonly TruffleHogOutputParser _parser;
    private readonly ScanExecutionContext _context;

    public TruffleHogOutputParserTests()
    {
        _parser = new TruffleHogOutputParser(NullLogger<TruffleHogOutputParser>.Instance);
        _context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/test-org/test-repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );
    }

    [Fact]
    public async Task ParseAsync_EmptyOrNullRawOutput_ReturnsEmptyCandidates()
    {
        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: "",
            StandardError: "",
            OutputSizeBytes: 0,
            DurationMs: 100
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Equal("trufflehog", result.ToolKey);
        Assert.Equal("3.96.0", result.Version);
        Assert.Empty(result.FindingCandidates);
        Assert.NotNull(result.Coverage);
        Assert.Equal(0, result.Coverage.AssetsProbed);
    }

    [Fact]
    public async Task ParseAsync_Exceeds10MiB_ReturnsTruncatedCoverage()
    {
        var hugeOutput = new string('A', 11 * 1024 * 1024);
        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: hugeOutput,
            StandardError: "",
            OutputSizeBytes: hugeOutput.Length,
            DurationMs: 100
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Empty(result.FindingCandidates);
        Assert.NotNull(result.Coverage);
        Assert.True(result.Coverage.CoverageTruncated);
        Assert.Equal("MaxRawOutputBytesExceeded", result.Coverage.CoverageTruncationReason);
    }

    [Fact]
    public async Task ParseAsync_JsonLinesFormat_ParsesVerifiedAndUnverifiedSecrets()
    {
        var line1 = @"{""SourceMetadata"":{""Data"":{""Filesystem"":{""file"":""appsettings.json"",""line"":12}}},""SourceID"":1,""SourceType"":15,""SourceName"":""trufflehog - filesystem"",""DetectorType"":8,""DetectorName"":""Github"",""DetectorDescription"":""GitHub personal access token detected"",""Verified"":true,""Raw"":""ghp_SECRET_RAW_TOKEN_12345"",""RawV2"":"""",""Redacted"":""ghp_SEC********2345"",""ExtraData"":{""rotation_guide"":""https://docs.github.com"",""version"":""1""}}";
        var line2 = @"{""SourceMetadata"":{""Data"":{""Filesystem"":{""file"":""src/config.ts"",""line"":45}}},""SourceID"":1,""SourceType"":15,""SourceName"":""trufflehog - filesystem"",""DetectorType"":27,""DetectorName"":""AWS"",""DetectorDescription"":""AWS IAM key identified"",""Verified"":false,""Raw"":""AKIA_RAW_KEY_UNVERIFIED"",""RawV2"":"""",""Redacted"":""AKIA_REDACTED"",""ExtraData"":{""account"":""123456789012""}}";

        var jsonLines = $"{line1}\n{line2}\n";

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: jsonLines,
            StandardError: "",
            OutputSizeBytes: Encoding.UTF8.GetByteCount(jsonLines),
            DurationMs: 250
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Equal(2, result.FindingCandidates.Count);

        var verifiedFinding = result.FindingCandidates[0];
        Assert.Equal(FindingType.ValidatedCredentialExposed, verifiedFinding.FindingType);
        Assert.Equal("critical", verifiedFinding.RawSeverity);
        Assert.Equal("Exposed & Validated Github Secret", verifiedFinding.Title);
        Assert.Equal("appsettings.json:12", verifiedFinding.VulnerableLocation);
        Assert.Equal("ghp_SEC********2345", verifiedFinding.ExtractedData);

        var unverifiedFinding = result.FindingCandidates[1];
        Assert.Equal(FindingType.UnvalidatedCredentialExposed, unverifiedFinding.FindingType);
        Assert.Equal("medium", unverifiedFinding.RawSeverity);
        Assert.Equal("Exposed AWS Credential Candidate", unverifiedFinding.Title);
        Assert.Equal("src/config.ts:45", unverifiedFinding.VulnerableLocation);
        Assert.Equal("AKIA_REDACTED", unverifiedFinding.ExtractedData);
    }

    [Fact]
    public async Task ParseAsync_ZeroRawSecretStorage_RawAndRawV2AreNeverPersisted()
    {
        var secretPayload = "SUPER_SENSITIVE_LIVE_API_KEY_NEVER_PERSIST_99999";
        var line = @"{""SourceMetadata"":{""Data"":{""Filesystem"":{""file"":""keys.env"",""line"":3}}},""DetectorName"":""Stripe"",""Verified"":true,""Raw"":""" + secretPayload + @""",""RawV2"":""" + secretPayload + @""",""Redacted"":""sk_live_****999""}";

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: line,
            StandardError: "",
            OutputSizeBytes: Encoding.UTF8.GetByteCount(line),
            DurationMs: 120
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Single(result.FindingCandidates);
        var finding = result.FindingCandidates[0];

        // Ensure raw secret payload does not exist in any candidate field
        Assert.DoesNotContain(secretPayload, finding.Title);
        Assert.DoesNotContain(secretPayload, finding.Description);
        Assert.DoesNotContain(secretPayload, finding.ExtractedData ?? "");
        Assert.DoesNotContain(secretPayload, finding.VulnerableLocation ?? "");
        Assert.DoesNotContain(secretPayload, finding.EndpointPath ?? "");
        Assert.DoesNotContain(secretPayload, finding.TargetUrl);

        if (finding.Attributes != null)
        {
            foreach (var kvp in finding.Attributes)
            {
                Assert.DoesNotContain(secretPayload, kvp.Key);
                Assert.DoesNotContain(secretPayload, kvp.Value);
            }
        }
    }

    [Fact]
    public async Task ParseAsync_JsonArrayFormat_ParsesSuccessfully()
    {
        var arrayJson = @"[
          {
            ""SourceMetadata"": { ""Data"": { ""Filesystem"": { ""file"": "".env.production"", ""line"": 7 } } },
            ""DetectorName"": ""Slack"",
            ""Verified"": true,
            ""Raw"": ""xoxb-secret-raw"",
            ""Redacted"": ""xoxb-redacted""
          }
        ]";

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: arrayJson,
            StandardError: "",
            OutputSizeBytes: Encoding.UTF8.GetByteCount(arrayJson),
            DurationMs: 100
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Single(result.FindingCandidates);
        Assert.Equal(FindingType.ValidatedCredentialExposed, result.FindingCandidates[0].FindingType);
        Assert.Equal(".env.production:7", result.FindingCandidates[0].VulnerableLocation);
    }

    [Fact]
    public async Task ParseAsync_MalformedLine_SkipsGracefullyAndIncrementsMalformedCount()
    {
        var malformedJsonLines = "NOT_A_JSON_LINE\n{\"DetectorName\":\"OpenAI\",\"Verified\":false,\"Redacted\":\"sk-proj-****\"}\n{broken json\n";

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: malformedJsonLines,
            StandardError: "",
            OutputSizeBytes: Encoding.UTF8.GetByteCount(malformedJsonLines),
            DurationMs: 150
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Single(result.FindingCandidates);
        Assert.Equal("Exposed OpenAI Credential Candidate", result.FindingCandidates[0].Title);
        Assert.NotNull(result.Coverage);
        Assert.Equal(2, result.Coverage.MalformedRecordCount);
    }

    [Fact]
    public async Task ParseAsync_SourceMetadataWithGit_ExtractsCommitAndFilePath()
    {
        var gitLine = @"{""SourceMetadata"":{""Data"":{""Git"":{""file"":""server/auth.go"",""line"":88,""commit"":""a1b2c3d4e5f6""}}},""DetectorName"":""Twilio"",""Verified"":true,""Redacted"":""AC_REDACTED""}";

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: gitLine,
            StandardError: "",
            OutputSizeBytes: Encoding.UTF8.GetByteCount(gitLine),
            DurationMs: 110
        );

        var result = await _parser.ParseAsync(_context, rawOutput);

        Assert.Single(result.FindingCandidates);
        var finding = result.FindingCandidates[0];
        Assert.Equal("server/auth.go:88", finding.VulnerableLocation);
        Assert.NotNull(finding.Attributes);
        Assert.Equal("a1b2c3d4e5f6", finding.Attributes["git_commit"]);
    }
}
