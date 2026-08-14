using System;
using System.Threading.Tasks;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class SubfinderAdapterTests
{
    private readonly SubfinderAdapter _adapter = new();

    private const string GoldenSubfinderOutputJson =
@"{""host"":""api.example.com"",""input"":""example.com"",""sources"":[""crtsh"",""virustotal""]}
{""host"":""auth.example.com"",""input"":""example.com"",""sources"":[""crtsh"",""securitytrails""]}
{""host"":""vpn.example.com"",""input"":""example.com"",""sources"":[""alienvault""]}";

    [Fact]
    public void Manifest_ConformsToPlatformSupplyChainValidation()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid);
        Assert.Equal("subfinder", _adapter.Manifest.ToolKey);
        Assert.Matches("^sha256:[a-f0-9]{64}$", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Recon, _adapter.Manifest.SupportedProfiles);
    }

    [Fact]
    public void PrepareExecution_ExtractsDomainAndBuildsPlan()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://example.com/api/v1",
            Profile: SecurityScanProfileType.Recon,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("subfinder", plan.ToolKey);
        Assert.Contains("-d", plan.CommandLineArguments);
        Assert.Contains("example.com", plan.CommandLineArguments);
        Assert.Contains("-json", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutputAsync_GoldenFileOutput_ExtractsSubdomainCandidates()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://example.com",
            Profile: SecurityScanProfileType.Recon,
            TenantId: Guid.NewGuid()
        );

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "subfinder",
            Version: "2.6.5",
            ExitCode: 0,
            StandardOutput: GoldenSubfinderOutputJson,
            StandardError: null,
            OutputSizeBytes: GoldenSubfinderOutputJson.Length,
            DurationMs: 2100
        );

        var result = await _adapter.ParseOutputAsync(context, rawOutput);

        Assert.Equal("subfinder", result.ToolKey);
        Assert.Equal(3, result.FindingCandidates.Count);
        Assert.NotNull(result.Coverage);
        Assert.Equal(3, result.Coverage.AssetsProbed);
    }
}
