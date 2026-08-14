using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Planning;

public class ScanPlanningEngineTests
{
    private readonly ScanToolRegistry _toolRegistry;
    private readonly ScanPlanningEngine _engine;

    public ScanPlanningEngineTests()
    {
        var httpxParser = new HttpxOutputParser();
        var nucleiParser = new NucleiOutputParser();
        var subfinderParser = new SubfinderOutputParser();
        var jsMinerParser = new JsMinerOutputParser(NullLogger<JsMinerOutputParser>.Instance);
        var bugHunterParser = new BugHunterOutputParser(NullLogger<BugHunterOutputParser>.Instance);
        var semgrepParser = new SemgrepOutputParser(NullLogger<SemgrepOutputParser>.Instance);

        var adapters = new IScanToolAdapter[]
        {
            new HttpxAdapter(httpxParser),
            new NucleiAdapter(nucleiParser),
            new SubfinderAdapter(subfinderParser),
            new JsMinerAdapter(jsMinerParser),
            new BugHunterAdapter(bugHunterParser),
            new SemgrepAdapter(semgrepParser)
        };

        _toolRegistry = new ScanToolRegistry(adapters);
        _engine = new ScanPlanningEngine(_toolRegistry, NullLogger<ScanPlanningEngine>.Instance);
    }

    [Fact]
    public void PlanScan_SourceRepositoryTarget_SelectsSemgrep()
    {
        var request = new ScanPlanningRequest(
            ScanJobId: Guid.NewGuid(),
            TenantId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            TargetKind: TargetAssetKind.SourceRepository,
            Profile: SecurityScanProfileType.Standard
        );

        var plan = _engine.PlanScan(request);

        Assert.Single(plan.PlannedInvocations);
        Assert.Equal("semgrep", plan.PlannedInvocations[0].ToolKey);
        Assert.Equal(ScannerExecutionPhase.StaticAnalysis, plan.PlannedInvocations[0].Phase);
        Assert.Contains("semgrep", plan.ExecutionSequence);
        Assert.NotNull(plan.PlanHash);
    }

    [Fact]
    public void PlanScan_JavaScriptBundleTarget_SelectsJsMiner()
    {
        var request = new ScanPlanningRequest(
            ScanJobId: Guid.NewGuid(),
            TenantId: Guid.NewGuid(),
            TargetUrl: "https://app.example.com/static/bundle.js",
            TargetKind: TargetAssetKind.JavaScriptBundle,
            Profile: SecurityScanProfileType.Deep
        );

        var plan = _engine.PlanScan(request);

        Assert.Single(plan.PlannedInvocations);
        Assert.Equal("jsminer", plan.PlannedInvocations[0].ToolKey);
        Assert.Equal(ScannerExecutionPhase.Discovery, plan.PlannedInvocations[0].Phase);
    }

    [Fact]
    public void PlanScan_WebEndpointStandard_SelectsHttpxAndNucleiInPhasedSequence()
    {
        var request = new ScanPlanningRequest(
            ScanJobId: Guid.NewGuid(),
            TenantId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard
        );

        var plan = _engine.PlanScan(request);

        // Discovery (httpx) must precede ActiveVerification (nuclei / bughunter)
        Assert.True(plan.PlannedInvocations.Count >= 2);
        var firstPhase = plan.PlannedInvocations[0].Phase;
        var lastPhase = plan.PlannedInvocations[^1].Phase;

        Assert.True((int)firstPhase <= (int)lastPhase);
        Assert.Equal("httpx", plan.PlannedInvocations[0].ToolKey);
    }

    [Fact]
    public void PlanScan_DisabledToolByPolicy_ExcludesDisabledTool()
    {
        var request = new ScanPlanningRequest(
            ScanJobId: Guid.NewGuid(),
            TenantId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com",
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            DisabledToolKeys: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "nuclei" }
        );

        var plan = _engine.PlanScan(request);

        Assert.DoesNotContain("nuclei", plan.ExecutionSequence);
        Assert.Contains("httpx", plan.ExecutionSequence);
    }

    [Fact]
    public void PlanScan_MultipleMatchingTools_AppliesSelectionPolicyPreference()
    {
        var customPolicy = new ScannerSelectionPolicy(
            Capability: "api.fuzz",
            PreferredToolKeys: new[] { "bughunter" },
            AllowMultipleTools: false
        );

        var request = new ScanPlanningRequest(
            ScanJobId: Guid.NewGuid(),
            TenantId: Guid.NewGuid(),
            TargetUrl: "https://api.example.com/v2/contract",
            TargetKind: TargetAssetKind.ApiContract,
            Profile: SecurityScanProfileType.Standard,
            RequiredCapabilities: new HashSet<string> { "api.fuzz" },
            CustomSelectionPolicies: new[] { customPolicy }
        );

        var plan = _engine.PlanScan(request);

        Assert.Single(plan.PlannedInvocations);
        Assert.Equal("bughunter", plan.PlannedInvocations[0].ToolKey);
    }

    [Fact]
    public void PlanScan_DeterministicPlanHash_ProducesIdenticalHashForSameInputs()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var request1 = new ScanPlanningRequest(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetUrl: "https://api.example.com",
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard
        );

        var request2 = new ScanPlanningRequest(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetUrl: "https://api.example.com",
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard
        );

        var plan1 = _engine.PlanScan(request1);
        var plan2 = _engine.PlanScan(request2);

        Assert.Equal(plan1.PlanHash, plan2.PlanHash);
        Assert.Equal(plan1.ExecutionSequence, plan2.ExecutionSequence);
    }

    [Fact]
    public async Task DiagnoseAllTools_AllRegisteredAdapters_ReturnsHealthyDiagnostics()
    {
        var reports = await _toolRegistry.DiagnoseAllToolsAsync();

        Assert.Equal(6, reports.Count);
        Assert.All(reports, r =>
        {
            Assert.Equal(ToolHealthStatus.Healthy, r.Status);
            Assert.True(r.IsContainerImageDigestValid);
            Assert.NotEmpty(r.DeclaredCapabilities);
            Assert.Null(r.ErrorMessage);
        });
    }
}
