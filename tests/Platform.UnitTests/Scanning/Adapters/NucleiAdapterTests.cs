using System;
using System.Threading.Tasks;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class NucleiAdapterTests
{
    private readonly NucleiAdapter _adapter = new();

    private const string GoldenNucleiOutputNdjson =
@"{""template-id"":""cve-2021-44228"",""info"":{""name"":""Apache Log4j RCE"",""author"":[""projectdiscovery""],""tags"":[""cve"",""rce"",""oast""],""severity"":""critical""},""type"":""http"",""host"":""https://api.example.com"",""matched-at"":""https://api.example.com/v1/auth"",""extracted-results"":[""ldap://127.0.0.1:1389/a""],""timestamp"":""2026-08-14T10:00:05.000Z""}
{""template-id"":""exposed-env-file"",""info"":{""name"":""Exposed .env Configuration File"",""author"":[""projectdiscovery""],""tags"":[""exposure"",""config""],""severity"":""high""},""type"":""http"",""host"":""https://api.example.com"",""matched-at"":""https://api.example.com/.env"",""extracted-results"":[""DB_PASSWORD=secret123""],""timestamp"":""2026-08-14T10:00:06.000Z""}";

    [Fact]
    public void Manifest_ConformsToPlatformSupplyChainValidation()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid);
        Assert.Equal("nuclei", _adapter.Manifest.ToolKey);
        Assert.Matches("^sha256:[a-f0-9]{64}$", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Deep, _adapter.Manifest.SupportedProfiles);
    }

    [Fact]
    public void PrepareExecution_BuildsAccurateCommandLinePlan()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Deep,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("nuclei", plan.ToolKey);
        Assert.Contains("-u", plan.CommandLineArguments);
        Assert.Contains("https://api.example.com", plan.CommandLineArguments);
        Assert.Contains("-jsonl", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutputAsync_GoldenFileOutput_ExtractsVulnerabilityCandidates()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Deep,
            TenantId: Guid.NewGuid()
        );

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "nuclei",
            Version: "3.2.0",
            ExitCode: 0,
            StandardOutput: GoldenNucleiOutputNdjson,
            StandardError: null,
            OutputSizeBytes: GoldenNucleiOutputNdjson.Length,
            DurationMs: 3400
        );

        var result = await _adapter.ParseOutputAsync(context, rawOutput);

        Assert.Equal("nuclei", result.ToolKey);
        Assert.Equal(2, result.FindingCandidates.Count);
        Assert.NotNull(result.Coverage);
        Assert.Equal(1, result.Coverage.AssetsProbed);
    }
}
