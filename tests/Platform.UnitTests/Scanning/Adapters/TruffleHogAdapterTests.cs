using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class TruffleHogAdapterTests
{
    private readonly TruffleHogAdapter _adapter;
    private readonly TruffleHogOutputParser _parser;

    public TruffleHogAdapterTests()
    {
        _parser = new TruffleHogOutputParser(NullLogger<TruffleHogOutputParser>.Instance);
        _adapter = new TruffleHogAdapter(_parser);
    }

    [Fact]
    public void Manifest_IsValidAccordingToContract()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal("trufflehog", _adapter.Manifest.ToolKey);
        Assert.Equal("3.96.0", _adapter.Manifest.Version);
        Assert.Equal("ghcr.io/trufflesecurity/trufflehog", _adapter.Manifest.ContainerImageRepository);
        Assert.Equal("ghcr.io/trufflesecurity/trufflehog:3.96.0", _adapter.Manifest.ContainerImageReference);
        Assert.Equal("sha256:b8acd9f7306d832b1f16e06003dac2283a737817954554111683ab7a56e9e539", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Deep, _adapter.Manifest.SupportedProfiles);
        Assert.Contains("secret.scan", _adapter.Manifest.Capabilities);
        Assert.Equal(ScannerExecutionPhase.StaticAnalysis, _adapter.Manifest.ExecutionPhase);
    }

    [Fact]
    public void PrepareExecution_StandardProfile_BuildsExpectedArguments()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("trufflehog", plan.ToolKey);
        Assert.Equal("3.96.0", plan.Version);
        Assert.Contains("filesystem", plan.CommandLineArguments);
        Assert.Contains(".", plan.CommandLineArguments);
        Assert.Contains("--json", plan.CommandLineArguments);
        Assert.Contains("--no-update", plan.CommandLineArguments);
        Assert.Contains("--fail=false", plan.CommandLineArguments);
        Assert.Contains("--no-verification", plan.CommandLineArguments);
        Assert.DoesNotContain("--archive-max-depth=5", plan.CommandLineArguments);
        Assert.Equal("true", plan.EnvironmentVariables["TRUFFLEHOG_NO_UPDATE"]);
        Assert.NotNull(plan.AdditionalMetadata);
        Assert.Equal("None", plan.AdditionalMetadata["NetworkBehavior"]);
        Assert.Equal("false", plan.AdditionalMetadata["RequiresEgressAuthorization"]);
    }

    [Fact]
    public void PrepareExecution_WithLiveVerificationOption_EnablesVerificationAndDeclaresEgressRequired()
    {
        var options = new Dictionary<string, string>
        {
            ["enable_live_verification"] = "true"
        };

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid(),
            AdditionalOptions: options
        );

        var plan = _adapter.PrepareExecution(context);

        // When live verification is authorized, --no-verification is omitted and egress is declared
        Assert.DoesNotContain("--no-verification", plan.CommandLineArguments);
        Assert.NotNull(plan.AdditionalMetadata);
        Assert.Equal("CredentialVerification", plan.AdditionalMetadata["NetworkBehavior"]);
        Assert.Equal("true", plan.AdditionalMetadata["RequiresEgressAuthorization"]);
    }

    [Fact]
    public void PrepareExecution_DeepProfile_IncludesArchiveExpansionFlags()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Deep,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Contains("--archive-max-depth=5", plan.CommandLineArguments);
        Assert.Contains("--archive-max-size=104857600", plan.CommandLineArguments);
    }

    [Fact]
    public void PrepareExecution_InjectsProviderSecrets()
    {
        var secrets = new Dictionary<string, string>
        {
            ["CUSTOM_SECRET_KEY"] = "secret_value_123"
        };

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid(),
            ProviderSecrets: secrets
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("secret_value_123", plan.EnvironmentVariables["CUSTOM_SECRET_KEY"]);
    }

    [Fact]
    public async Task ParseOutputAsync_DelegatesToParserAndReturnsFindings()
    {
        var line = @"{""SourceMetadata"":{""Data"":{""Filesystem"":{""file"":""config.json"",""line"":20}}},""DetectorName"":""Postman"",""Verified"":true,""Redacted"":""PMAK-64****""}";
        var rawOutput = new ToolExecutionRawOutput(
            ToolKey: "trufflehog",
            Version: "3.96.0",
            ExitCode: 0,
            StandardOutput: line,
            StandardError: "",
            OutputSizeBytes: line.Length,
            DurationMs: 150
        );

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var result = await _adapter.ParseOutputAsync(context, rawOutput);

        Assert.Single(result.FindingCandidates);
        Assert.Equal("Exposed & Validated Postman Secret", result.FindingCandidates[0].Title);
        Assert.Equal(FindingType.ValidatedCredentialExposed, result.FindingCandidates[0].FindingType);
    }

    [Fact]
    public void ScanToolRegistry_AcceptsTruffleHogAdapterWithoutValidationErrors()
    {
        var registry = new ScanToolRegistry(new IScanToolAdapter[] { _adapter });

        var registered = registry.GetAdapter("trufflehog");
        Assert.NotNull(registered);
        Assert.Equal("3.96.0", registered.Manifest.Version);

        var secretTools = registry.GetAdaptersForCapability("secret.scan");
        Assert.Single(secretTools);
        Assert.Equal("trufflehog", secretTools[0].Manifest.ToolKey);
    }
}
