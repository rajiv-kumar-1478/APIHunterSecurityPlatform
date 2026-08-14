using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class HttpxAdapterTests
{
    private readonly HttpxAdapter _adapter = new();

    private const string GoldenHttpxOutputJson = @"[
  {
    ""timestamp"": ""2026-08-14T10:00:00.000Z"",
    ""url"": ""https://api.example.com"",
    ""input"": ""https://api.example.com"",
    ""status_code"": 200,
    ""title"": ""API Gateway"",
    ""webserver"": ""nginx/1.24.0"",
    ""tech"": [""Nginx"", ""Node.js"", ""Express""],
    ""content_length"": 1024,
    ""scheme"": ""https"",
    ""port"": ""443"",
    ""path"": ""/""
  },
  {
    ""timestamp"": ""2026-08-14T10:00:01.000Z"",
    ""url"": ""https://api.example.com/admin/login"",
    ""input"": ""https://api.example.com/admin/login"",
    ""status_code"": 403,
    ""title"": ""Forbidden Admin"",
    ""webserver"": ""nginx/1.24.0"",
    ""tech"": [""Nginx""],
    ""content_length"": 256,
    ""scheme"": ""https"",
    ""port"": ""443"",
    ""path"": ""/admin/login""
  }
]";

    [Fact]
    public void Manifest_ConformsToPlatformSupplyChainValidation()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid);
        Assert.Equal("httpx", _adapter.Manifest.ToolKey);
        Assert.Matches("^sha256:[a-f0-9]{64}$", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Recon, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
    }

    [Fact]
    public void PrepareExecution_BuildsAccurateCommandLinePlan()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("httpx", plan.ToolKey);
        Assert.Contains("-u", plan.CommandLineArguments);
        Assert.Contains("https://api.example.com", plan.CommandLineArguments);
        Assert.Contains("-json", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutputAsync_GoldenFileOutput_ExtractsCandidatesAndCoverage()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "httpx",
            Version: "1.6.0",
            ExitCode: 0,
            StandardOutput: GoldenHttpxOutputJson,
            StandardError: null,
            OutputSizeBytes: GoldenHttpxOutputJson.Length,
            DurationMs: 1200
        );

        var result = await _adapter.ParseOutputAsync(context, rawOutput);

        Assert.Equal("httpx", result.ToolKey);
        Assert.Equal(2, result.FindingCandidates.Count);
        Assert.NotNull(result.Coverage);
        Assert.True(result.Coverage.EndpointsDiscovered >= 2);
    }
}
