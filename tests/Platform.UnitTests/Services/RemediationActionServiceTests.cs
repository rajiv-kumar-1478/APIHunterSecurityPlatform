using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class RemediationActionServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly RemediationActionService _service;

    public RemediationActionServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("RemediationDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_userId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");
        _mockUserContext.Setup(u => u.IsPlatformAdmin).Returns(true);

        _service = new RemediationActionService(_dbContext, _mockAuditService.Object, _mockUserContext.Object, new RemediationRecommendationEngine(), new ResponsePolicyEngine(), new ResponsePolicyOptions());
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, SecurityFinding Finding)> SeedFindingAsync()
    {
        var repo = new Repository { FullName = "octocat/remediation-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            Title = "Exposed Validated Key",
            Description = "OpenAI key exposed in repo",
            Status = FindingStatus.Open,
            RiskScore = 90,
            RiskFactorBreakdownJson = "[{\"code\":\"BASE\",\"weight\":60}]"
        };
        _dbContext.SecurityFindings.Add(finding);

        await _dbContext.SaveChangesAsync();
        return (repo, finding);
    }

    // ─── Test 1: Creates proposed remediation action ─────────────────────────

    [Fact]
    public async Task Test1_Creates_Proposed_RemediationAction()
    {
        var (repo, finding) = await SeedFindingAsync();

        var request = new CreateRemediationActionRequest(
            FindingId: finding.Id,
            ActionType: RemediationActionType.RevokeCredential,
            Title: "Revoke Exposed OpenAI Key",
            Description: "Revoke candidate key at provider",
            ProviderKey: "openai",
            ProviderResourceReference: "sk-proj-****1234",
            ExpiryHours: 24);

        var action = await _service.CreateActionAsync(request);

        Assert.NotNull(action);
        Assert.Equal(finding.Id, action.FindingId);
        Assert.Equal(repo.Id, action.RepositoryId);
        Assert.Equal(RemediationActionStatus.Proposed, action.Status);
        Assert.True(action.RequiresApproval);
        Assert.Equal(90, action.PreExecutionRiskScore);
        Assert.Equal(1, action.Version);
        Assert.NotNull(action.ExpiresAtUtc);
    }

    // ─── Test 2: Links action to correct finding and repository ──────────────

    [Fact]
    public async Task Test2_Links_Action_To_Correct_Finding_And_Repository()
    {
        var (repo, finding) = await SeedFindingAsync();

        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(
            finding.Id, RemediationActionType.RotateCredential, "Rotate Key", "Rotate key"));

        Assert.Equal(finding.Id, action.FindingId);
        Assert.Equal(repo.Id, action.RepositoryId);
    }

    // ─── Test 3: Rejects nonexistent finding ──────────────────────────────────

    [Fact]
    public async Task Test3_Rejects_NonExistent_Finding()
    {
        var fakeId = Guid.NewGuid();
        var request = new CreateRemediationActionRequest(fakeId, RemediationActionType.RevokeCredential, "Title", "Desc");

        await Assert.ThrowsAsync<KeyNotFoundException>(() => _service.CreateActionAsync(request));
    }

    // ─── Test 5: Action fingerprint deduplicates active creation requests ─────

    [Fact]
    public async Task Test5_ActionFingerprint_Deduplicates_Active_Duplicate_Creation_Requests()
    {
        var (repo, finding) = await SeedFindingAsync();

        var request1 = new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title 1", "Desc 1", "openai", "res-1");
        var request2 = new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title 2", "Desc 2", "openai", "res-1");

        var action1 = await _service.CreateActionAsync(request1);
        var action2 = await _service.CreateActionAsync(request2);

        Assert.Equal(action1.Id, action2.Id);
    }

    // ─── Test 6: Proposed -> PendingApproval succeeds ─────────────────────────

    [Fact]
    public async Task Test6_Proposed_To_PendingApproval_Succeeds()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));

        var updated = await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
            action.Id, RemediationActionStatus.PendingApproval, ExpectedVersion: 1, Reason: "Submitting for security triage"));

        Assert.Equal(RemediationActionStatus.PendingApproval, updated.Status);
        Assert.Equal(2, updated.Version);
    }

    // ─── Test 7: PendingApproval -> Approved populates approval fields ────────

    [Fact]
    public async Task Test7_PendingApproval_To_Approved_Populates_ApprovalFields()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.PendingApproval, 1, "Triage"));

        var approved = await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
            action.Id, RemediationActionStatus.Approved, ExpectedVersion: 2, Reason: "Approved by Lead SecOps"));

        Assert.Equal(RemediationActionStatus.Approved, approved.Status);
        Assert.Equal(_userId, approved.ApprovedByUserId);
        Assert.NotNull(approved.ApprovedAtUtc);
        Assert.Equal("Approved by Lead SecOps", approved.ApprovalReason);
    }

    // ─── Test 8: PendingApproval -> Rejected populates rejection fields ────────

    [Fact]
    public async Task Test8_PendingApproval_To_Rejected_Populates_RejectionFields()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.PendingApproval, 1, "Triage"));

        var rejected = await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
            action.Id, RemediationActionStatus.Rejected, ExpectedVersion: 2, Reason: "Rejected: Key is sandbox test key"));

        Assert.Equal(RemediationActionStatus.Rejected, rejected.Status);
        Assert.Equal(_userId, rejected.RejectedByUserId);
        Assert.NotNull(rejected.RejectedAtUtc);
        Assert.Equal("Rejected: Key is sandbox test key", rejected.RejectionReason);
    }

    // ─── Test 9: Invalid state transition path throws InvalidOperationException

    [Fact]
    public async Task Test9_Invalid_State_Transition_Throws_InvalidOperationException()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));

        // Proposed directly to Executing (bypassing PendingApproval / Approved)
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
                action.Id, RemediationActionStatus.Executing, ExpectedVersion: 1, Reason: "Direct execute")));
    }

    // ─── Test 10: Stale version token throws DbUpdateConcurrencyException ──────

    [Fact]
    public async Task Test10_Stale_Version_Token_Throws_ConcurrencyException()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));

        // ExpectedVersion is 99 (stale / mismatch)
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
                action.Id, RemediationActionStatus.PendingApproval, ExpectedVersion: 99, Reason: "Mismatch")));
    }

    // ─── Test 11: History appended for every status transition ───────────────

    [Fact]
    public async Task Test11_History_Appended_For_Every_Status_Transition()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.PendingApproval, 1, "Reason 1"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.Approved, 2, "Reason 2"));

        var history = await _service.GetActionHistoryAsync(action.Id);

        Assert.Equal(3, history.Count);
        Assert.Equal(RemediationActionStatus.Proposed, history[0].ToStatus);
        Assert.Equal(RemediationActionStatus.PendingApproval, history[1].ToStatus);
        Assert.Equal(RemediationActionStatus.Approved, history[2].ToStatus);
    }

    // ─── Test 12: Raw secret forbidden in all action fields ───────────────────

    [Fact]
    public async Task Test12_RawSecret_Forbidden_In_All_Action_Fields()
    {
        var (repo, finding) = await SeedFindingAsync();
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(
            finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc", "openai", "sk-proj-****1234"));

        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            action.Id,
            action.Title,
            action.Description,
            action.ActionFingerprint,
            action.ProviderKey,
            action.ProviderResourceReference
        });

        Assert.DoesNotContain("sk-proj-live-secret-raw-value", json);
        Assert.DoesNotContain("EncryptedRawValue", json);
    }

    // ─── Test 13: Expired approval lease rejects transition to execution ─────

    [Fact]
    public async Task Test13_Expired_Approval_Lease_Rejects_Transition_To_Execution_State()
    {
        var (repo, finding) = await SeedFindingAsync();

        // Create action with -1 expiry hours (expired immediately)
        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(
            finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc", ExpiryHours: -1));

        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.PendingApproval, 1, "Triage"));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(
                action.Id, RemediationActionStatus.Approved, 2, "Approval attempt")));
    }

    // ─── Test 14: FindingStatus and CandidateStatus preserved unchanged ──────

    [Fact]
    public async Task Test14_FindingStatus_And_CandidateStatus_Preserved_Unchanged()
    {
        var (repo, finding) = await SeedFindingAsync();
        var initialFindingStatus = finding.Status;

        var action = await _service.CreateActionAsync(new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.PendingApproval, 1, "Reason"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action.Id, RemediationActionStatus.Approved, 2, "Reason"));

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(initialFindingStatus, freshFinding!.Status);
    }

    // ─── Test 16: Terminal action allows new action creation ───────────────────

    [Fact]
    public async Task Test16_TerminalAction_Allows_New_Action_Creation()
    {
        var (repo, finding) = await SeedFindingAsync();
        var request = new CreateRemediationActionRequest(finding.Id, RemediationActionType.RevokeCredential, "Title", "Desc", "openai", "res-1");

        var action1 = await _service.CreateActionAsync(request);
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action1.Id, RemediationActionStatus.PendingApproval, 1, "Triage"));
        await _service.TransitionStatusAsync(new TransitionRemediationActionStatusRequest(action1.Id, RemediationActionStatus.Rejected, 2, "Rejected"));

        // Second creation request with same fingerprint after action1 is terminal (Rejected)
        var action2 = await _service.CreateActionAsync(request);

        Assert.NotEqual(action1.Id, action2.Id);
        Assert.Equal(RemediationActionStatus.Proposed, action2.Status);
    }
}
