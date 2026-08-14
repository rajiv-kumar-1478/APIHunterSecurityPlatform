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

public class BugHunterAdapterTests
{
    private readonly BugHunterAdapter _adapter;
    private readonly BugHunterOutputParser _parser;

    public BugHunterAdapterTests()
    {
        _parser = new BugHunterOutputParser(NullLogger<BugHunterOutputParser>.Instance);
        _adapter = new BugHunterAdapter(_parser);
    }

    [Fact]
    public void Manifest_IsValidAccordingToContract()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal("bughunter", _adapter.Manifest.ToolKey);
        Assert.Equal("2.1.0", _adapter.Manifest.Version);
        Assert.StartsWith("sha256:", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Deep, _adapter.Manifest.SupportedProfiles);
    }

    [Fact]
    public void PrepareExecution_BuildsAccuratePlan()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Deep,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("bughunter", plan.ToolKey);
        Assert.Contains("-u", plan.CommandLineArguments);
        Assert.Contains("https://api.example.com", plan.CommandLineArguments);
        Assert.Contains("-verify-bola", plan.CommandLineArguments);
        Assert.Contains("-verify-tamper", plan.CommandLineArguments);
        Assert.Contains("-verify-contract", plan.CommandLineArguments);
        Assert.Contains("-verify-graphql", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutput_BolaAndTamperingFindings_ExtractsCorrectFindingCandidates()
    {
        var jsonLines = string.Join("\n", new[]
        {
            "{\"type\":\"tested_metric\",\"endpoints\":25,\"params\":80}",
            "{\"type\":\"finding\",\"id\":\"BOLA-001\",\"name\":\"Broken Object Level Authorization on User Resource\",\"severity\":\"high\",\"endpoint\":\"https://api.example.com/api/v2/users/105\",\"method\":\"GET\",\"param\":\"id\",\"description\":\"User 105 accessible without ownership.\",\"cwe\":\"CWE-284\"}",
            "{\"type\":\"finding\",\"id\":\"PARAM-TAMPER-002\",\"name\":\"Role Parameter Tampering\",\"severity\":\"critical\",\"endpoint\":\"https://api.example.com/api/v2/users/105/role\",\"method\":\"PUT\",\"param\":\"role\",\"description\":\"Privilege escalation via role parameter.\",\"cwe\":\"CWE-269\"}"
        });

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("bughunter", "2.1.0", 0, jsonLines, string.Empty, Encoding.UTF8.GetByteCount(jsonLines), 350);
        var result = await _adapter.ParseOutputAsync(context, raw);

        Assert.Equal(2, result.FindingCandidates.Count);

        var bolaCandidate = result.FindingCandidates.First(c => c.RuleOrTemplateId == "BOLA-001");
        Assert.Equal(FindingType.ProductionServiceExposed, bolaCandidate.FindingType);
        Assert.Equal("high", bolaCandidate.RawSeverity);
        Assert.Equal("id", bolaCandidate.ParameterName);
        Assert.Equal("CWE-284", bolaCandidate.CweId);

        var tamperCandidate = result.FindingCandidates.First(c => c.RuleOrTemplateId == "PARAM-TAMPER-002");
        Assert.Equal(FindingType.ProductionServiceExposed, tamperCandidate.FindingType);
        Assert.Equal("critical", tamperCandidate.RawSeverity);
        Assert.Equal("role", tamperCandidate.ParameterName);

        Assert.Equal(25, result.Coverage.EndpointsDiscovered);
        Assert.Equal(80, result.Coverage.ParametersExtracted);
    }
}
