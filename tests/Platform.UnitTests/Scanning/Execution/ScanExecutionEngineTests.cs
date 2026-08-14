using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Execution;
using Platform.Application.Scanning.Execution.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning.Execution;

public class ScanExecutionEngineTests
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanToolRegistry _toolRegistry;
    private readonly ScanExecutionEngine _engine;

    public ScanExecutionEngineTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: $"ExecutionTestDb_{Guid.NewGuid()}")
            .Options;

        _dbContext = new PlatformDbContext(options);

        var httpxParser = new HttpxOutputParser();
        var nucleiParser = new NucleiOutputParser();
        var bugHunterParser = new BugHunterOutputParser(NullLogger<BugHunterOutputParser>.Instance);
        var semgrepParser = new SemgrepOutputParser(NullLogger<SemgrepOutputParser>.Instance);

        var adapters = new IScanToolAdapter[]
        {
            new HttpxAdapter(httpxParser),
            new NucleiAdapter(nucleiParser),
            new BugHunterAdapter(bugHunterParser),
            new SemgrepAdapter(semgrepParser)
        };

        _toolRegistry = new ScanToolRegistry(adapters);
        _engine = new ScanExecutionEngine(_toolRegistry, _dbContext, NullLogger<ScanExecutionEngine>.Instance);
    }

    [Fact]
    public async Task ExecutePlan_AllToolsSucceed_ReturnsCompletedStatus()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var invocations = new List<PlannedToolInvocation>
        {
            new("httpx", "1.6.8", ScannerExecutionPhase.Discovery, new[] { "http.probe" }, Array.Empty<string>(), "Discovery"),
            new("semgrep", "1.172.0", ScannerExecutionPhase.StaticAnalysis, new[] { "sast.scan" }, Array.Empty<string>(), "SAST")
        };

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.SourceRepository,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: invocations.AsReadOnly(),
            ExecutionSequence: new[] { "httpx", "semgrep" },
            RuleSetVersions: new Dictionary<string, string> { ["httpx"] = "1.6.8", ["semgrep"] = "1.172.0" },
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "hash_success_123",
            PlannedAtUtc: DateTime.UtcNow
        );

        var result = await _engine.ExecutePlanAsync(plan);

        Assert.Equal(OverallScanExecutionStatus.Completed, result.OverallStatus);
        Assert.Equal(2, result.Invocations.Count);
        Assert.All(result.Invocations, i => Assert.Equal(ToolInvocationStatus.Completed, i.Status));

        // Check DB persisted records
        var dbRecords = await _dbContext.ScanToolInvocations
            .Where(i => i.ScanJobId == scanJobId)
            .ToListAsync();

        Assert.Equal(2, dbRecords.Count);
        Assert.All(dbRecords, r =>
        {
            Assert.Equal("Completed", r.Status);
            Assert.Equal("hash_success_123", r.PlanHash);
            Assert.NotEmpty(r.ContainerImageDigest);
        });
    }

    [Fact]
    public async Task ExecutePlan_OneToolFails_ReturnsCompletedWithToolFailures()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var invocations = new List<PlannedToolInvocation>
        {
            new("httpx", "1.6.8", ScannerExecutionPhase.Discovery, new[] { "http.probe" }, Array.Empty<string>(), "Discovery"),
            new("unregistered_tool", "1.0.0", ScannerExecutionPhase.ActiveVerification, new[] { "custom.scan" }, Array.Empty<string>(), "Fails")
        };

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: invocations.AsReadOnly(),
            ExecutionSequence: new[] { "httpx", "unregistered_tool" },
            RuleSetVersions: new Dictionary<string, string>(),
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "hash_partial_123",
            PlannedAtUtc: DateTime.UtcNow
        );

        var result = await _engine.ExecutePlanAsync(plan);

        Assert.Equal(OverallScanExecutionStatus.CompletedWithToolFailures, result.OverallStatus);
        Assert.Equal(2, result.Invocations.Count);
        Assert.Equal(ToolInvocationStatus.Completed, result.Invocations[0].Status);
        Assert.Equal(ToolInvocationStatus.Failed, result.Invocations[1].Status);
        Assert.Contains("not registered", result.Invocations[1].ErrorMessage);
    }

    [Fact]
    public async Task GetExecutionSummary_ValidJob_ReturnsOrderedTimelineForDashboard()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var invocations = new List<PlannedToolInvocation>
        {
            new("httpx", "1.6.8", ScannerExecutionPhase.Discovery, new[] { "http.probe" }, Array.Empty<string>(), "Discovery"),
            new("nuclei", "3.3.0", ScannerExecutionPhase.ActiveVerification, new[] { "template.vulnerability" }, Array.Empty<string>(), "Active verification")
        };

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: invocations.AsReadOnly(),
            ExecutionSequence: new[] { "httpx", "nuclei" },
            RuleSetVersions: new Dictionary<string, string> { ["httpx"] = "1.6.8", ["nuclei"] = "3.3.0" },
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "plan_timeline_123",
            PlannedAtUtc: DateTime.UtcNow
        );

        await _engine.ExecutePlanAsync(plan);

        var summary = await _engine.GetExecutionSummaryAsync(scanJobId, tenantId);

        Assert.NotNull(summary);
        Assert.Equal(scanJobId, summary.ScanJobId);
        Assert.Equal("plan_timeline_123", summary.PlanHash);
        Assert.Equal(OverallScanExecutionStatus.Completed, summary.OverallStatus);
        Assert.Equal(2, summary.TotalToolsPlanned);
        Assert.Equal(2, summary.ToolsCompleted);
        Assert.Equal(0, summary.ToolsFailed);
        Assert.Equal(2, summary.Invocations.Count);
        Assert.Equal("httpx", summary.Invocations[0].ToolKey);
        Assert.Equal("nuclei", summary.Invocations[1].ToolKey);
    }

    [Fact]
    public async Task GetExecutionSummary_WrongTenantOrMissingJob_ReturnsNull()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();

        var invocations = new List<PlannedToolInvocation>
        {
            new("httpx", "1.6.8", ScannerExecutionPhase.Discovery, new[] { "http.probe" }, Array.Empty<string>(), "Discovery")
        };

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: invocations.AsReadOnly(),
            ExecutionSequence: new[] { "httpx" },
            RuleSetVersions: new Dictionary<string, string>(),
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "plan_tenant_isolation",
            PlannedAtUtc: DateTime.UtcNow
        );

        await _engine.ExecutePlanAsync(plan);

        var summary = await _engine.GetExecutionSummaryAsync(scanJobId, otherTenantId);

        Assert.Null(summary);
    }
}
