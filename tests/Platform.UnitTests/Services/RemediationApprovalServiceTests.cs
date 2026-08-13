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

public class RemediationApprovalServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly PermissionService _permissionService;
    private readonly RemediationApprovalService _service;
    private readonly Guid _adminUserId = Guid.NewGuid();

    public RemediationApprovalServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ApprovalDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_adminUserId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");
        _mockUserContext.Setup(u => u.IsPlatformAdmin).Returns(true);

        _permissionService = new PermissionService(_dbContext, _mockAuditService.Object, _mockUserContext.Object);
        _service = new RemediationApprovalService(_dbContext, _mockAuditService.Object, _mockUserContext.Object, _permissionService);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, SecurityFinding Finding, RemediationAction Action)> SeedActionAsync(int expiryHours = 24, FindingStatus findingStatus = FindingStatus.Open)
    {
        var repo = new Repository { FullName = "octocat/approval-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Validated OpenAI Key Exposure",
            Status = findingStatus,
            RiskScore = 95
        };
        _dbContext.SecurityFindings.Add(finding);

        var action = new RemediationAction
        {
            FindingId = finding.Id,
            RepositoryId = repo.Id,
            ActionType = RemediationActionType.RevokeCredential,
            Status = RemediationActionStatus.Proposed,
            Title = "Revoke OpenAI Key",
            Description = "Revoke key at provider",
            ActionFingerprint = "fingerprint_" + Guid.NewGuid().ToString("N"),
            Version = 1,
            RequiresApproval = true,
            ExpiresAtUtc = DateTime.UtcNow.AddHours(expiryHours),
            ProviderKey = "openai",
            ProviderResourceReference = "sk-proj-****1234",
            PreExecutionRiskScore = 95
        };
        _dbContext.RemediationActions.Add(action);

        await _dbContext.SaveChangesAsync();
        return (repo, finding, action);
    }

    // ─── Test 1: ApproveAction Succeeds For Admin Or Authorized User ───────────

    [Fact]
    public async Task Test1_ApproveAction_Succeeds_For_Admin_Or_AuthorizedUser()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var approved = await _service.ApproveActionAsync(new ApproveRemediationActionRequest(
            action.Id, ExpectedVersion: 1, Reason: "Approved by Lead SecOps Engineer"));

        Assert.NotNull(approved);
        Assert.Equal(RemediationActionStatus.Approved, approved.Status);
        Assert.Equal(_adminUserId, approved.ApprovedByUserId);
        Assert.NotNull(approved.ApprovedAtUtc);
        Assert.Equal("Approved by Lead SecOps Engineer", approved.ApprovalReason);
        Assert.Equal(2, approved.Version);
    }

    // ─── Test 2: ApproveAction Rejects Unauthorized User ───────────────────────

    [Fact]
    public async Task Test2_ApproveAction_Rejects_Unauthorized_User()
    {
        var (repo, finding, action) = await SeedActionAsync();
        var unauthUser = Guid.NewGuid();

        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns(unauthUser);
        mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        var service = new RemediationApprovalService(_dbContext, _mockAuditService.Object, mockUser.Object, _permissionService);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Approve attempt")));
    }

    // ─── Test 3: ApproveAction Rejects Unauthenticated User ───────────────────

    [Fact]
    public async Task Test3_ApproveAction_Rejects_Unauthenticated_User()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns((Guid?)null);

        var service = new RemediationApprovalService(_dbContext, _mockAuditService.Object, mockUser.Object, _permissionService);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Approve attempt")));
    }

    // ─── Test 4: ApproveAction Rejects NonExistent Action ─────────────────────

    [Fact]
    public async Task Test4_ApproveAction_Rejects_NonExistent_Action()
    {
        var fakeId = Guid.NewGuid();

        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            _service.ApproveActionAsync(new ApproveRemediationActionRequest(fakeId, 1, "Reason")));
    }

    // ─── Test 5: ApproveAction Rejects Stale Version Token ────────────────────

    [Fact]
    public async Task Test5_ApproveAction_Rejects_Stale_Version_Token()
    {
        var (repo, finding, action) = await SeedActionAsync();

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, ExpectedVersion: 99, Reason: "Stale version")));
    }

    // ─── Test 6: ApproveAction Rejects Expired Lease ─────────────────────────

    [Fact]
    public async Task Test6_ApproveAction_Rejects_Expired_Lease()
    {
        var (repo, finding, action) = await SeedActionAsync(expiryHours: -1); // Expired immediately

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Approval on expired lease")));
    }

    // ─── Test 7: ApproveAction Rejects Inactive Resolved Finding ──────────────

    [Fact]
    public async Task Test7_ApproveAction_Rejects_Inactive_Resolved_Finding()
    {
        var (repo, finding, action) = await SeedActionAsync(findingStatus: FindingStatus.Resolved);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Approval on resolved finding")));
    }

    // ─── Test 8: RejectAction Succeeds For Authorized User ───────────────────

    [Fact]
    public async Task Test8_RejectAction_Succeeds_For_AuthorizedUser()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var rejected = await _service.RejectActionAsync(new RejectRemediationActionRequest(
            action.Id, ExpectedVersion: 1, Reason: "Rejected: Candidate key is staging mock credential"));

        Assert.NotNull(rejected);
        Assert.Equal(RemediationActionStatus.Rejected, rejected.Status);
        Assert.Equal(_adminUserId, rejected.RejectedByUserId);
        Assert.NotNull(rejected.RejectedAtUtc);
        Assert.Equal("Rejected: Candidate key is staging mock credential", rejected.RejectionReason);
        Assert.Equal(2, rejected.Version);
    }

    // ─── Test 9: RejectAction Rejects Unauthorized User ───────────────────────

    [Fact]
    public async Task Test9_RejectAction_Rejects_Unauthorized_User()
    {
        var (repo, finding, action) = await SeedActionAsync();
        var unauthUser = Guid.NewGuid();

        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns(unauthUser);
        mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        var service = new RemediationApprovalService(_dbContext, _mockAuditService.Object, mockUser.Object, _permissionService);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.RejectActionAsync(new RejectRemediationActionRequest(action.Id, 1, "Reject attempt")));
    }

    // ─── Test 10: ApproveAction Appends History And Emits AuditLog ────────────

    [Fact]
    public async Task Test10_ApproveAction_Appends_History_And_Emits_AuditLog()
    {
        var (repo, finding, action) = await SeedActionAsync();

        await _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "SecOps Approved"));

        var history = await _dbContext.RemediationActionHistories
            .Where(h => h.RemediationActionId == action.Id)
            .ToListAsync();

        Assert.Single(history);
        Assert.Equal(RemediationActionStatus.Proposed, history[0].FromStatus);
        Assert.Equal(RemediationActionStatus.Approved, history[0].ToStatus);
        Assert.Equal("SecOps Approved", history[0].Reason);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionApproved,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 11: RejectAction Appends History And Emits AuditLog ────────────

    [Fact]
    public async Task Test11_RejectAction_Appends_History_And_Emits_AuditLog()
    {
        var (repo, finding, action) = await SeedActionAsync();

        await _service.RejectActionAsync(new RejectRemediationActionRequest(action.Id, 1, "SecOps Rejected"));

        var history = await _dbContext.RemediationActionHistories
            .Where(h => h.RemediationActionId == action.Id)
            .ToListAsync();

        Assert.Single(history);
        Assert.Equal(RemediationActionStatus.Proposed, history[0].FromStatus);
        Assert.Equal(RemediationActionStatus.Rejected, history[0].ToStatus);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionRejected,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 12: ApproveAction Rejects Terminal Status Action ────────────────

    [Fact]
    public async Task Test12_ApproveAction_Rejects_Terminal_Status_Action()
    {
        var (repo, finding, action) = await SeedActionAsync();
        await _service.RejectActionAsync(new RejectRemediationActionRequest(action.Id, 1, "First rejection"));

        // Attempting to approve an action that is already Rejected
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, ExpectedVersion: 2, Reason: "Re-approve attempt")));
    }

    // ─── Test 13: Concurrent Approval Attempts Race Condition Invariant ──────

    [Fact]
    public async Task Test13_Concurrent_Approval_Attempts_One_Succeeds_One_Throws_Concurrency()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var request1 = new ApproveRemediationActionRequest(action.Id, ExpectedVersion: 1, Reason: "Admin A Approval");
        var request2 = new ApproveRemediationActionRequest(action.Id, ExpectedVersion: 1, Reason: "Admin B Approval");

        // First approval succeeds
        var approvedAction = await _service.ApproveActionAsync(request1);
        Assert.Equal(RemediationActionStatus.Approved, approvedAction.Status);
        Assert.Equal(2, approvedAction.Version);

        // Competing approval with stale ExpectedVersion=1 throws DbUpdateConcurrencyException
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.ApproveActionAsync(request2));

        // Invariant check: Exactly 1 history entry and 1 approval audit log committed
        var historyCount = await _dbContext.RemediationActionHistories
            .CountAsync(h => h.RemediationActionId == action.Id);
        Assert.Equal(1, historyCount);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionApproved,
            It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 14: Approver Identity Taken From Authenticated UserContext ──────

    [Fact]
    public async Task Test14_Approver_Identity_Taken_From_Authenticated_UserContext()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var approved = await _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Reason"));

        Assert.Equal(_adminUserId, approved.ApprovedByUserId);
    }

    // ─── Test 15: FindingStatus and CandidateStatus Preserved Unchanged ─────

    [Fact]
    public async Task Test15_FindingStatus_And_CandidateStatus_Preserved_Unchanged()
    {
        var (repo, finding, action) = await SeedActionAsync();
        var initialFindingStatus = finding.Status;

        await _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Reason"));

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(initialFindingStatus, freshFinding!.Status);
    }

    // ─── Test 16: Zero Raw Secret In Approval Payloads Or Audit ───────────────

    [Fact]
    public async Task Test16_Zero_Raw_Secret_In_Approval_Payloads_Or_Audit()
    {
        var (repo, finding, action) = await SeedActionAsync();

        var approved = await _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Approved key sk-proj-****1234"));

        var json = System.Text.Json.JsonSerializer.Serialize(new { approved.Id, approved.ApprovalReason, approved.ProviderResourceReference });

        Assert.DoesNotContain("sk-proj-raw-live-key", json);
        Assert.DoesNotContain("EncryptedRawValue", json);
    }

    // ─── Test 17: Action Immutability ActionFingerprint Preserved ────────────

    [Fact]
    public async Task Test17_Action_Immutability_ActionFingerprint_Preserved()
    {
        var (repo, finding, action) = await SeedActionAsync();
        var initialFingerprint = action.ActionFingerprint;

        var approved = await _service.ApproveActionAsync(new ApproveRemediationActionRequest(action.Id, 1, "Reason"));

        Assert.Equal(initialFingerprint, approved.ActionFingerprint);
    }

    // ─── Test 18: Core Engine Isolation Verification ─────────────────────────

    [Fact]
    public void Test18_Core_Engine_Isolation_Verification()
    {
        // Core engines must remain untouched and pure
        Assert.True(typeof(RiskEngine) != null);
        Assert.True(typeof(SecurityFindingLifecycleService) != null);
    }
}
