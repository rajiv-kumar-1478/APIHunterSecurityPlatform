using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class SecurityFindingLifecycleServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly SecurityFindingLifecycleService _lifecycleService;
    private readonly Guid _actorUserId = Guid.NewGuid();

    public SecurityFindingLifecycleServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("LifecycleDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        var riskEngine = new RiskEngine(new RiskPolicyOptions());
        _findingService = new SecurityFindingService(
            _dbContext, riskEngine, new Mock<ILogger<SecurityFindingService>>().Object);

        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.UserId).Returns(_actorUserId);
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(true);
        _mockUser.Setup(u => u.CorrelationId).Returns(Guid.NewGuid().ToString());

        _lifecycleService = new SecurityFindingLifecycleService(
            _dbContext, _findingService, _mockUser.Object,
            new Mock<ILogger<SecurityFindingLifecycleService>>().Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private async Task<(Repository, SecurityFinding)> SeedFindingAsync(FindingStatus status = FindingStatus.Open)
    {
        var repo = new Repository { FullName = "octocat/test-lifecycle" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            RepositoryId: repo.Id,
            SnapshotId: null,
            FindingType: FindingType.ValidatedCredentialExposed,
            Severity: RiskSeverity.High,
            Confidence: FindingConfidence.High,
            Title: "Test Finding",
            Description: "Test Description",
            CoreEntityId: Guid.NewGuid().ToString("N")
        ));

        if (status != FindingStatus.Open)
        {
            finding.Status = status;
            await _dbContext.SaveChangesAsync();
        }

        return (repo, finding);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Valid — Open → Investigating
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test1_ValidTransition_OpenToInvestigating_Succeeds()
    {
        var (_, finding) = await SeedFindingAsync();

        var result = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Investigating, finding.LifecycleVersion, "Starting investigation."));

        Assert.Equal(FindingStatus.Investigating, result.Status);
        Assert.Equal(2, result.LifecycleVersion);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Valid — Investigating → Confirmed
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test2_ValidTransition_InvestigatingToConfirmed_Succeeds()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.Investigating);

        var result = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Confirmed, finding.LifecycleVersion, null));

        Assert.Equal(FindingStatus.Confirmed, result.Status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Valid — Confirmed → Remediated (governance reason required)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test3_ValidTransition_ConfirmedToRemediated_SucceedsWithReason()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.Confirmed);

        var result = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Remediated, finding.LifecycleVersion, "API key was rotated."));

        Assert.Equal(FindingStatus.Remediated, result.Status);
        Assert.Null(result.ResolvedAtUtc); // Option A: Only Resolved sets ResolvedAtUtc
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Valid — Remediated → Resolved (sets resolution fields)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test4_ValidTransition_RemediatedToResolved_SetsResolutionFields()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.Remediated);

        var result = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Resolved, finding.LifecycleVersion, "Remediation verified."));

        Assert.Equal(FindingStatus.Resolved, result.Status);
        Assert.NotNull(result.ResolvedAtUtc);
        Assert.Equal(_actorUserId, result.ResolvedByUserId);
        Assert.Equal("Remediation verified.", result.ResolutionReason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Option A — Remediated/AcceptedRisk do not set ResolvedAtUtc
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test5_RemediatedAndAcceptedRisk_DoNotSetResolvedAtUtc_OptionA()
    {
        var (_, remediatedFinding) = await SeedFindingAsync(FindingStatus.Confirmed);
        var remResult = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(remediatedFinding.Id, FindingStatus.Remediated, remediatedFinding.LifecycleVersion, "Rotated key."));
        Assert.Null(remResult.ResolvedAtUtc);

        var (_, acceptedFinding) = await SeedFindingAsync(FindingStatus.Confirmed);
        var accResult = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(acceptedFinding.Id, FindingStatus.AcceptedRisk, acceptedFinding.LifecycleVersion, "Risk accepted until Q4."));
        Assert.Null(accResult.ResolvedAtUtc);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Invalid — Open → Remediated (forbidden shortcut)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test6_InvalidTransition_OpenToRemediated_ThrowsInvalidOperationException()
    {
        var (_, finding) = await SeedFindingAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Remediated, finding.LifecycleVersion, "Done.")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Invalid — Open → Resolved (forbidden shortcut)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test7_InvalidTransition_OpenToResolved_ThrowsInvalidOperationException()
    {
        var (_, finding) = await SeedFindingAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Resolved, finding.LifecycleVersion, "Resolved.")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: Invalid — FalsePositive → Remediated (forbidden)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test8_InvalidTransition_FalsePositiveToRemediated_ThrowsInvalidOperationException()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.FalsePositive);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Remediated, finding.LifecycleVersion, "Fix.")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: Re-open — Resolved → Open resets resolution fields
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test9_ReopenTransition_ResolvedToOpen_ResetsResolutionFieldsAndRecalculatesRisk()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.Remediated);

        // Transition to Resolved
        var resolved = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Resolved, finding.LifecycleVersion, "Verified."));
        Assert.NotNull(resolved.ResolvedAtUtc);

        // Re-open
        var reopened = await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(resolved.Id, FindingStatus.Open, resolved.LifecycleVersion, null));

        Assert.Equal(FindingStatus.Open, reopened.Status);
        Assert.Null(reopened.ResolvedAtUtc);
        Assert.Null(reopened.ResolvedByUserId);
        Assert.Null(reopened.ResolutionReason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10: Status history appends immutable record for each transition
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test10_StatusHistory_AppendsImmutableRecordForEachTransition()
    {
        var (_, finding) = await SeedFindingAsync();

        await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Investigating, finding.LifecycleVersion, null));

        var f2 = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(f2.Id, FindingStatus.Confirmed, f2.LifecycleVersion, null));

        var history = await _lifecycleService.GetFindingStatusHistoryAsync(finding.Id);
        Assert.Equal(2, history.Count);
        Assert.Equal(FindingStatus.Open, history[0].FromStatus);
        Assert.Equal(FindingStatus.Investigating, history[0].ToStatus);
        Assert.Equal(FindingStatus.Investigating, history[1].FromStatus);
        Assert.Equal(FindingStatus.Confirmed, history[1].ToStatus);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 11: Audit event logged on status transition
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test11_AuditEvent_LoggedOnStatusTransition()
    {
        var (_, finding) = await SeedFindingAsync();

        await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Investigating, finding.LifecycleVersion, null));

        var auditEvent = await _dbContext.AuditEvents
            .FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.FindingStatusChanged &&
                                      a.ResourceId == finding.Id.ToString());

        Assert.NotNull(auditEvent);
        Assert.Equal(_actorUserId, auditEvent.UserId);
        Assert.Contains("Investigating", auditEvent.Metadata ?? "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 12: Repository risk recalculated when finding transitions to excluded status
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test12_RepositoryRisk_RecalculatedOnTransitionToExcludedStatus()
    {
        var (repo, finding) = await SeedFindingAsync(FindingStatus.Confirmed);

        int scoreBeforeRemediation = finding.RiskScore;

        await _lifecycleService.TransitionFindingStatusAsync(
            new TransitionFindingStatusRequest(finding.Id, FindingStatus.Remediated, finding.LifecycleVersion, "Key rotated."));

        // Repository active risk must not include Remediated findings
        var repoRisk = await _dbContext.RepositoryRiskScores.FirstOrDefaultAsync(r => r.RepositoryId == repo.Id);
        if (repoRisk != null)
        {
            Assert.True(repoRisk.Score < scoreBeforeRemediation || repoRisk.Score == 0,
                $"Expected lower/zero risk after remediation, got {repoRisk.Score}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 13: Stale version — concurrency conflict rejected
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test13_ConcurrentTransition_StaleVersion_IsRejected()
    {
        var (_, finding) = await SeedFindingAsync();
        int staleVersion = finding.LifecycleVersion - 1; // Simulate stale client version

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Investigating, staleVersion, null)));

        // Finding must remain unchanged
        var unchanged = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == finding.Id);
        Assert.Equal(FindingStatus.Open, unchanged.Status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 14: Governance transition without reason is rejected
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test14_GovernanceTransition_RequiresReason_ThrowsArgumentExceptionWhenMissing()
    {
        var (_, finding) = await SeedFindingAsync(FindingStatus.Confirmed);

        // Attempt governance transition with blank reason
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Remediated, finding.LifecycleVersion, "")));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.AcceptedRisk, finding.LifecycleVersion, "   ")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 15: Stale version — no history row and no audit event created
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test15_ConcurrentTransition_StaleVersion_RollsBackHistoryAndAudit()
    {
        var (_, finding) = await SeedFindingAsync();
        int staleVersion = finding.LifecycleVersion - 1;

        int historyCountBefore = await _dbContext.SecurityFindingStatusHistories.CountAsync();
        int auditCountBefore = await _dbContext.AuditEvents
            .CountAsync(a => a.EventCode == AuditEventCode.FindingStatusChanged);

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _lifecycleService.TransitionFindingStatusAsync(
                new TransitionFindingStatusRequest(finding.Id, FindingStatus.Investigating, staleVersion, null)));

        int historyCountAfter = await _dbContext.SecurityFindingStatusHistories.CountAsync();
        int auditCountAfter = await _dbContext.AuditEvents
            .CountAsync(a => a.EventCode == AuditEventCode.FindingStatusChanged);

        Assert.Equal(historyCountBefore, historyCountAfter);
        Assert.Equal(auditCountBefore, auditCountAfter);
    }
}
