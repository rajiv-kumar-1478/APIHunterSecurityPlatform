using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Audit;
using Platform.Application.Scanning.Audit.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning.Audit;

public class ScanPlanAuditServiceTests
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanToolRegistry _toolRegistry;
    private readonly ScanPlanAuditService _service;

    public ScanPlanAuditServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: $"AuditTestDb_{Guid.NewGuid()}")
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
        _service = new ScanPlanAuditService(_dbContext, NullLogger<ScanPlanAuditService>.Instance);
    }

    [Fact]
    public async Task RecordPlanAudit_FirstPlan_CreatesGenesisChainedRecord()
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
            SelectionReasons: new Dictionary<string, string> { ["httpx"] = "HTTP probe", ["nuclei"] = "CVE detect" },
            PlannerVersion: "1.0.0",
            PlanHash: "a1b2c3d4e5f6",
            PlannedAtUtc: DateTime.UtcNow
        );

        var record = await _service.RecordPlanAuditAsync(plan, _toolRegistry);

        Assert.NotNull(record);
        Assert.Equal(scanJobId, record.ScanJobId);
        Assert.Equal(tenantId, record.TenantId);
        Assert.Equal(ScanPlanAuditService.GenesisAuditHash, record.PreviousAuditHash);
        Assert.NotEmpty(record.RecordHash);
        Assert.NotEmpty(record.RegistrySnapshotHash);
    }

    [Fact]
    public async Task RecordPlanAudit_SubsequentPlan_ChainsToPreviousRecordHash()
    {
        var tenantId = Guid.NewGuid();

        var plan1 = new ResolvedScanPlan(
            ScanJobId: Guid.NewGuid(),
            TenantId: tenantId,
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: new List<PlannedToolInvocation>().AsReadOnly(),
            ExecutionSequence: new[] { "httpx" },
            RuleSetVersions: new Dictionary<string, string>(),
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "hash1",
            PlannedAtUtc: DateTime.UtcNow
        );

        var plan2 = new ResolvedScanPlan(
            ScanJobId: Guid.NewGuid(),
            TenantId: tenantId,
            TargetKind: TargetAssetKind.SourceRepository,
            Profile: SecurityScanProfileType.Deep,
            PlannedInvocations: new List<PlannedToolInvocation>().AsReadOnly(),
            ExecutionSequence: new[] { "semgrep" },
            RuleSetVersions: new Dictionary<string, string>(),
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "hash2",
            PlannedAtUtc: DateTime.UtcNow.AddSeconds(1)
        );

        var record1 = await _service.RecordPlanAuditAsync(plan1, _toolRegistry);
        var record2 = await _service.RecordPlanAuditAsync(plan2, _toolRegistry);

        Assert.Equal(record1.RecordHash, record2.PreviousAuditHash);
        Assert.NotEqual(record1.RecordHash, record2.RecordHash);
    }

    [Fact]
    public async Task GetProvenance_ExistingJob_ReturnsFullAuditSnapshot()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.SourceRepository,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: new List<PlannedToolInvocation>
            {
                new("semgrep", "1.172.0", ScannerExecutionPhase.StaticAnalysis, new[] { "sast.scan" }, Array.Empty<string>(), "SAST code scan")
            }.AsReadOnly(),
            ExecutionSequence: new[] { "semgrep" },
            RuleSetVersions: new Dictionary<string, string> { ["semgrep"] = "1.172.0" },
            SelectionReasons: new Dictionary<string, string> { ["semgrep"] = "SAST" },
            PlannerVersion: "1.0.0",
            PlanHash: "plan_semgrep_123",
            PlannedAtUtc: DateTime.UtcNow
        );

        await _service.RecordPlanAuditAsync(plan, _toolRegistry);

        var provenance = await _service.GetProvenanceAsync(scanJobId, tenantId);

        Assert.NotNull(provenance);
        Assert.Equal(scanJobId, provenance.ScanJobId);
        Assert.Equal("plan_semgrep_123", provenance.PlanHash);
        Assert.Contains("semgrep", provenance.ExecutionSequence);
        Assert.NotEmpty(provenance.ToolManifestSnapshots);

        var semgrepManifest = provenance.ToolManifestSnapshots.FirstOrDefault(m => m.ToolKey == "semgrep");
        Assert.NotNull(semgrepManifest);
        Assert.Equal("1.172.0", semgrepManifest.Version);
        Assert.StartsWith("sha256:", semgrepManifest.ContainerImageDigest);
    }

    [Fact]
    public async Task GetProvenance_WrongTenantOrMissingJob_ReturnsNull()
    {
        var scanJobId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();

        var plan = new ResolvedScanPlan(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            TargetKind: TargetAssetKind.WebEndpoint,
            Profile: SecurityScanProfileType.Standard,
            PlannedInvocations: new List<PlannedToolInvocation>().AsReadOnly(),
            ExecutionSequence: new[] { "httpx" },
            RuleSetVersions: new Dictionary<string, string>(),
            SelectionReasons: new Dictionary<string, string>(),
            PlannerVersion: "1.0.0",
            PlanHash: "plan123",
            PlannedAtUtc: DateTime.UtcNow
        );

        await _service.RecordPlanAuditAsync(plan, _toolRegistry);

        var result = await _service.GetProvenanceAsync(scanJobId, otherTenantId);

        Assert.Null(result);
    }
}
