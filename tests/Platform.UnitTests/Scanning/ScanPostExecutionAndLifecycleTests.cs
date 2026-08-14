using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanPostExecutionAndLifecycleTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly TestUserContext _userContext;
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly ScanJobService _scanJobService;
    private readonly ScanPostExecutionProcessor _processor;
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();

    public ScanPostExecutionAndLifecycleTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ScanPostExecutionTests_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _userContext = new TestUserContext();
        _toolRegistry = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _scanJobService = new ScanJobService(_dbContext, _userContext, _toolRegistry, NullLogger<ScanJobService>.Instance);

        var mockAuditService = new Mock<IAuditService>();
        var recEngine = new RemediationRecommendationEngine();
        var respEngine = new ResponsePolicyEngine();
        var remediationService = new RemediationActionService(
            _dbContext,
            mockAuditService.Object,
            _userContext,
            recEngine,
            respEngine,
            new ResponsePolicyOptions { Enabled = true }
        );

        _processor = new ScanPostExecutionProcessor(
            _dbContext,
            _scanJobService,
            NullLogger<ScanPostExecutionProcessor>.Instance,
            remediationService,
            Options.Create(new ResponsePolicyOptions { Enabled = true })
        );

        // Seed Repository & SecurityTarget
        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "TargetRepo",
            FullName = "org/TargetRepo",
            Owner = "org",
            Url = "https://github.com/org/TargetRepo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Authorized Web Target",
            BaseUrl = "https://api.example.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    [Fact]
    public async Task BuildSummary_ComputesAccurateMetricsFromPersistedData()
    {
        var receipt = new ScanExecutionReceipt(
            JobId: Guid.NewGuid(),
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:abc", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-2), DateTime.UtcNow, 45000, 1024, 2, 2, 0, null, ToolFailureClassification.None),
                new ToolExecutionReceipt("httpx", "v1.4", "httpx", "ghcr.io/httpx", "sha256:def", SecurityScanProfileType.Standard, ScanExecutionPhase.Probing, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-4), DateTime.UtcNow.AddMinutes(-2), 30000, 2048, 1, 1, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 3,
            TotalFindingsUpdated: 0,
            Summary: "Scan completed with 3 findings."
        );

        var job = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-6),
            CompletedAtUtc = DateTime.UtcNow
        };

        var finding1 = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "fp1",
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            FindingType = FindingType.ValidatedCredentialExposed,
            Title = "API Secret Exposed",
            Description = "Secret leak",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow
        };

        var finding2 = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "fp2",
            Severity = RiskSeverity.High,
            Confidence = FindingConfidence.High,
            FindingType = FindingType.ProductionServiceExposed,
            Title = "SQL Injection in auth",
            Description = "SQLi",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.Add(job);
        _dbContext.SecurityFindings.AddRange(finding1, finding2);

        _dbContext.ScanFindingObservations.AddRange(
            new ScanFindingObservation { FindingId = finding1.Id, ScanJobId = job.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "hash1" },
            new ScanFindingObservation { FindingId = finding2.Id, ScanJobId = job.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "hash1" }
        );

        await _dbContext.SaveChangesAsync();

        var summary = await _processor.BuildSummaryAsync(job.Id);

        summary.ScanJobId.Should().Be(job.Id);
        summary.TargetId.Should().Be(_targetId);
        summary.JobStatus.Should().Be(SecurityScanJobStatus.Completed);
        summary.CriticalCount.Should().Be(1);
        summary.HighCount.Should().Be(1);
        summary.FindingsTotal.Should().Be(2);
        summary.ToolsAttempted.Should().Be(2);
        summary.ToolsSucceeded.Should().Be(2);
        summary.ToolsFailed.Should().Be(0);
        summary.FindingsByTool.Should().ContainKey("nuclei");
        summary.FindingsByTool["nuclei"].Should().Be(2);
    }

    [Fact]
    public async Task CalculateDiff_IdentifiesNewAndPersistentFindings()
    {
        var baselineJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };

        var currentJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow
        };

        var findingOld = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "persistent_fp",
            Severity = RiskSeverity.High,
            Title = "Persistent SQL Injection",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };

        var findingNew = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "new_fp",
            Severity = RiskSeverity.Medium,
            Title = "New XSS vulnerability",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.AddRange(baselineJob, currentJob);
        _dbContext.SecurityFindings.AddRange(findingOld, findingNew);

        // Baseline observed findingOld
        _dbContext.ScanFindingObservations.Add(new ScanFindingObservation
        {
            FindingId = findingOld.Id,
            ScanJobId = baselineJob.Id,
            WasObserved = true,
            FullCoverageConfirmed = true,
            ToolCoverageHash = "base_hash"
        });

        // Current observed findingOld (persistent) and findingNew (new)
        _dbContext.ScanFindingObservations.AddRange(
            new ScanFindingObservation { FindingId = findingOld.Id, ScanJobId = currentJob.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "curr_hash" },
            new ScanFindingObservation { FindingId = findingNew.Id, ScanJobId = currentJob.Id, WasObserved = true, FullCoverageConfirmed = true, ToolCoverageHash = "curr_hash" }
        );

        await _dbContext.SaveChangesAsync();

        var diff = await _processor.CalculateDiffAsync(currentJob.Id, baselineJob.Id);

        diff.NewFindings.Should().ContainSingle(f => f.FindingFingerprint == "new_fp");
        diff.PersistentFindings.Should().ContainSingle(f => f.FindingFingerprint == "persistent_fp");
        diff.NotObservedFindings.Should().BeEmpty();
    }

    [Fact]
    public async Task ProcessLifecycle_FirstAbsence_SetsNotObserved_DoesNotResolve()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "absent_fp1",
            Severity = RiskSeverity.High,
            Title = "Intermittent Bug",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1),
            LastObservedAtUtc = DateTime.UtcNow.AddDays(-1)
        };

        var receipt = CreateSuccessfulReceipt(Guid.NewGuid());
        var scanJob = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5)
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.Add(scanJob);
        await _dbContext.SaveChangesAsync();

        // Process first absent scan
        await _processor.ProcessPostScanLifecycleAsync(scanJob.Id);

        var reloadedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        reloadedFinding.Status.Should().Be(FindingStatus.Open, "A single absent scan must not automatically resolve the finding");

        var obs = await _dbContext.ScanFindingObservations.FirstOrDefaultAsync(o => o.FindingId == finding.Id && o.ScanJobId == scanJob.Id);
        obs.Should().NotBeNull();
        obs!.WasObserved.Should().BeFalse();
        obs.FullCoverageConfirmed.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessLifecycle_SecondConsecutiveAbsence_WithFullCoverage_ResolvesFinding()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "absent_fp2",
            Severity = RiskSeverity.High,
            Title = "Fixed Vulnerability",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-2),
            LastObservedAtUtc = DateTime.UtcNow.AddDays(-2)
        };

        // Scan 1 (Previous scan: absent + full coverage)
        var scan1Id = Guid.NewGuid();
        var scan1 = new SecurityScanJob
        {
            Id = scan1Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };

        var obs1 = new ScanFindingObservation
        {
            Id = Guid.NewGuid(),
            FindingId = finding.Id,
            ScanJobId = scan1Id,
            ObservedAtUtc = DateTime.UtcNow.AddHours(-2),
            WasObserved = false,
            FullCoverageConfirmed = true,
            ToolCoverageHash = "hash1"
        };

        // Scan 2 (Current scan: absent + full coverage)
        var receipt2 = CreateSuccessfulReceipt(Guid.NewGuid());
        var scan2 = new SecurityScanJob
        {
            Id = receipt2.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt2),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.AddRange(scan1, scan2);
        _dbContext.ScanFindingObservations.Add(obs1);
        await _dbContext.SaveChangesAsync();

        // Process Scan 2
        await _processor.ProcessPostScanLifecycleAsync(scan2.Id);

        var resolvedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        resolvedFinding.Status.Should().Be(FindingStatus.Resolved, "Two consecutive confirmed absences must automatically resolve the finding");
        resolvedFinding.ResolutionReason.Should().Be("ConfirmedAbsenceAcrossConsecutiveScans");
        resolvedFinding.ResolvedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task ProcessLifecycle_IncompleteScanOrToolFailure_DoesNotAdvanceResolution()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "incomplete_scan_fp",
            Severity = RiskSeverity.High,
            Title = "Finding",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-2),
            LastObservedAtUtc = DateTime.UtcNow.AddDays(-2)
        };

        // Scan 1: absent + full coverage
        var scan1Id = Guid.NewGuid();
        var scan1 = new SecurityScanJob
        {
            Id = scan1Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };
        var obs1 = new ScanFindingObservation
        {
            Id = Guid.NewGuid(),
            FindingId = finding.Id,
            ScanJobId = scan1Id,
            ObservedAtUtc = DateTime.UtcNow.AddHours(-2),
            WasObserved = false,
            FullCoverageConfirmed = true,
            ToolCoverageHash = "hash1"
        };

        // Scan 2: Incomplete / fatal sandbox crash
        var receipt2 = new ScanExecutionReceipt(
            JobId: Guid.NewGuid(),
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.CompletedWithWarnings,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:abc", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Failed, DateTime.UtcNow.AddMinutes(-2), DateTime.UtcNow, 1000, 0, 0, 0, 0, "Container crashed", ToolFailureClassification.SecurityBoundary)
            },
            TotalFindingsCreated: 0,
            TotalFindingsUpdated: 0,
            Summary: "Fatal sandbox crash."
        );

        var scan2 = new SecurityScanJob
        {
            Id = receipt2.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.CompletedWithWarnings,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt2),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.AddRange(scan1, scan2);
        _dbContext.ScanFindingObservations.Add(obs1);
        await _dbContext.SaveChangesAsync();

        // Process Scan 2
        await _processor.ProcessPostScanLifecycleAsync(scan2.Id);

        var reloadedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        reloadedFinding.Status.Should().Be(FindingStatus.Open, "An incomplete scan or sandbox crash must not satisfy consecutive absence resolution");
    }

    [Fact]
    public async Task ProcessLifecycle_DifferentProfile_DoesNotIncorrectlySatisfyConsecutiveAbsence()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "diff_profile_fp",
            Severity = RiskSeverity.High,
            Title = "Finding",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-2),
            LastObservedAtUtc = DateTime.UtcNow.AddDays(-2)
        };

        // Scan 1: Recon profile (does not cover Standard vulnerability scanning)
        var scan1Id = Guid.NewGuid();
        var scan1 = new SecurityScanJob
        {
            Id = scan1Id,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            CreatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };
        var obs1 = new ScanFindingObservation
        {
            Id = Guid.NewGuid(),
            FindingId = finding.Id,
            ScanJobId = scan1Id,
            ObservedAtUtc = DateTime.UtcNow.AddHours(-2),
            WasObserved = false,
            FullCoverageConfirmed = true,
            ToolCoverageHash = "hash1"
        };

        // Scan 2: Standard profile
        var receipt2 = CreateSuccessfulReceipt(Guid.NewGuid());
        var scan2 = new SecurityScanJob
        {
            Id = receipt2.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt2),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.AddRange(scan1, scan2);
        _dbContext.ScanFindingObservations.Add(obs1);
        await _dbContext.SaveChangesAsync();

        await _processor.ProcessPostScanLifecycleAsync(scan2.Id);

        var reloadedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        reloadedFinding.Status.Should().Be(FindingStatus.Open, "A different scan profile (Recon) cannot satisfy consecutive absence for Standard profile");
    }

    [Fact]
    public async Task ProcessLifecycle_Reappearance_ResetsAbsenceHistory_ReopensFinding()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "reappearing_fp",
            Severity = RiskSeverity.High,
            Title = "Reappearing Issue",
            Description = "desc",
            Status = FindingStatus.Resolved,
            ResolutionReason = "ConfirmedAbsenceAcrossConsecutiveScans",
            ResolvedAtUtc = DateTime.UtcNow.AddDays(-1),
            CreatedAtUtc = DateTime.UtcNow.AddDays(-5),
            LastObservedAtUtc = DateTime.UtcNow // observed now
        };

        var receipt = CreateSuccessfulReceipt(Guid.NewGuid());
        var scanJob = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5)
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.Add(scanJob);
        await _dbContext.SaveChangesAsync();

        await _processor.ProcessPostScanLifecycleAsync(scanJob.Id);

        var reloadedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        reloadedFinding.Status.Should().Be(FindingStatus.Open, "Reappearance must re-open previously resolved finding to Open status");
        reloadedFinding.ResolvedAtUtc.Should().BeNull();
        reloadedFinding.ResolutionReason.Should().BeNull();
    }

    [Fact]
    public async Task ProcessLifecycle_DuplicatePostProcessing_IsIdempotent()
    {
        var finding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "idempotent_fp",
            Severity = RiskSeverity.Medium,
            Title = "Idempotency Test",
            Description = "desc",
            Status = FindingStatus.Open,
            CreatedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow
        };

        var receipt = CreateSuccessfulReceipt(Guid.NewGuid());
        var scanJob = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5)
        };

        _dbContext.SecurityFindings.Add(finding);
        _dbContext.SecurityScanJobs.Add(scanJob);
        await _dbContext.SaveChangesAsync();

        // Run post-processing twice
        await _processor.ProcessPostScanLifecycleAsync(scanJob.Id);
        await _processor.ProcessPostScanLifecycleAsync(scanJob.Id);

        var observations = await _dbContext.ScanFindingObservations
            .Where(o => o.FindingId == finding.Id && o.ScanJobId == scanJob.Id)
            .ToListAsync();

        observations.Should().HaveCount(1, "Duplicate post-processing must not create duplicate observation records");
    }

    [Fact]
    public async Task ProcessLifecycle_CriticalAndHighFindings_ProposesRemediation_StatusProposedOnly()
    {
        var criticalFinding = new SecurityFinding
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            FindingFingerprint = "crit_remediation_fp",
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            FindingType = FindingType.ValidatedCredentialExposed,
            Title = "Critical Leaked Token",
            Description = "AWS access key leaked",
            Status = FindingStatus.Open,
            RiskScore = 95,
            CreatedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityFindingEvidences.Add(new SecurityFindingEvidence
        {
            Id = Guid.NewGuid(),
            FindingId = criticalFinding.Id,
            EvidenceFingerprint = "ev1",
            EvidenceReference = "https://api.example.com/api/v1/auth",
            SafeEvidenceJson = "{\"cveId\":null,\"toolKey\":\"nuclei\"}",
            CreatedAtUtc = DateTime.UtcNow
        });

        var receipt = CreateSuccessfulReceipt(Guid.NewGuid());
        var scanJob = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            RequestedByUserId = _userContext.UserId!.Value,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5)
        };

        _dbContext.SecurityFindings.Add(criticalFinding);
        _dbContext.SecurityScanJobs.Add(scanJob);
        await _dbContext.SaveChangesAsync();

        await _processor.ProcessPostScanLifecycleAsync(scanJob.Id);

        var remediationActions = await _dbContext.RemediationActions
            .Where(a => a.FindingId == criticalFinding.Id)
            .ToListAsync();

        remediationActions.Should().NotBeEmpty();
        remediationActions[0].Status.Should().Be(RemediationActionStatus.Proposed, "Remediation action must strictly be in Proposed status with zero auto-execution");
    }

    private static ScanExecutionReceipt CreateSuccessfulReceipt(Guid jobId)
    {
        return new ScanExecutionReceipt(
            JobId: jobId,
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("subfinder", "v2.6", "subfinder", "ghcr.io/subfinder", "sha256:111", SecurityScanProfileType.Standard, ScanExecutionPhase.Discovery, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddMinutes(-4), 10000, 512, 1, 1, 0, null, ToolFailureClassification.None),
                new ToolExecutionReceipt("httpx", "v1.4", "httpx", "ghcr.io/httpx", "sha256:222", SecurityScanProfileType.Standard, ScanExecutionPhase.Probing, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-4), DateTime.UtcNow.AddMinutes(-2), 20000, 1024, 1, 1, 0, null, ToolFailureClassification.None),
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:333", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-2), DateTime.UtcNow, 30000, 2048, 1, 1, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 1,
            TotalFindingsUpdated: 0,
            Summary: "Standard scan completed successfully."
        );
    }

    private class TestUserContext : ICurrentUserContext
    {
        public Guid? UserId { get; set; } = Guid.NewGuid();
        public string? SessionId { get; set; } = "session-test";
        public bool IsAuthenticated { get; set; } = true;
        public bool IsPlatformAdmin { get; set; } = true;
        public string CorrelationId { get; set; } = "corr-test";
        public string IpAddress { get; set; } = "127.0.0.1";
    }
}
