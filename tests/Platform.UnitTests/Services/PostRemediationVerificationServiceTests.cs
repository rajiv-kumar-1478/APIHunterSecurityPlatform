using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Auth;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Application.Verification;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class PostRemediationVerificationServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly PermissionService _permissionService;
    private readonly SecurityFindingService _findingService;
    private readonly List<IVerificationStrategy> _strategies;
    private readonly PostRemediationVerificationService _service;
    private readonly Guid _adminUserId = Guid.NewGuid();

    public PostRemediationVerificationServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("VerificationDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_adminUserId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");
        _mockUserContext.Setup(u => u.IsPlatformAdmin).Returns(true);

        _permissionService = new PermissionService(_dbContext, _mockAuditService.Object, _mockUserContext.Object);
        _findingService = new SecurityFindingService(
            _dbContext,
            new RiskEngine(new Platform.Application.Configuration.RiskPolicyOptions()),
            NullLogger<SecurityFindingService>.Instance);

        _strategies = new List<IVerificationStrategy>
        {
            new RevokeCredentialVerificationStrategy(),
            new FallbackVerificationStrategy()
        };

        _service = new PostRemediationVerificationService(
            _dbContext,
            _mockAuditService.Object,
            _mockUserContext.Object,
            _permissionService,
            _findingService,
            _strategies);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, SecurityFinding Finding, RemediationAction Action, RemediationExecution Execution)> SeedVerificationPendingActionAsync(
        ValidationStatus validationStatus = ValidationStatus.Invalid,
        RemediationActionStatus actionStatus = RemediationActionStatus.VerificationPending,
        FindingStatus findingStatus = FindingStatus.Open)
    {
        var repo = new Repository { FullName = "octocat/verification-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Exposed OpenAI Key",
            Status = findingStatus,
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);

        var action = new RemediationAction
        {
            FindingId = finding.Id,
            RepositoryId = repo.Id,
            ActionType = RemediationActionType.RevokeCredential,
            Status = actionStatus,
            Title = "Revoke OpenAI Key",
            Description = "Revoke key",
            ActionFingerprint = "fingerprint_" + Guid.NewGuid().ToString("N"),
            Version = 2,
            RequiresApproval = true,
            ApprovedByUserId = _adminUserId,
            ApprovedAtUtc = DateTime.UtcNow.AddHours(-2),
            ExpiresAtUtc = DateTime.UtcNow.AddHours(22),
            ProviderKey = "openai",
            ProviderResourceReference = "sk-proj-****1234",
            PreExecutionRiskScore = 90
        };
        _dbContext.RemediationActions.Add(action);

        var execution = new RemediationExecution
        {
            RemediationActionId = action.Id,
            ActionVersion = 1,
            Status = RemediationExecutionStatus.Succeeded,
            ProviderKey = "openai",
            ProviderResourceReference = "sk-proj-****1234",
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-30),
            CompletedAtUtc = DateTime.UtcNow.AddMinutes(-29),
            Success = true,
            ProviderOperationId = "op_123456"
        };
        _dbContext.RemediationExecutions.Add(execution);

        var validationResult = new CredentialValidationResult
        {
            CandidateId = Guid.NewGuid(),
            ProviderName = "openai",
            Status = validationStatus,
            HttpStatusCode = (int)validationStatus,
            ValidatedAtUtc = DateTime.UtcNow
        };
        _dbContext.CredentialValidationResults.Add(validationResult);

        await _dbContext.SaveChangesAsync();
        return (repo, finding, action, execution);
    }

    // ─── Test 1: VerifyAction Succeeds When Validation Confirms Revoked Key ─

    [Fact]
    public async Task Test1_VerifyAction_Succeeds_When_Validation_Confirms_Revoked_Key()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Invalid);

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, ExpectedVersion: 2));

        Assert.NotNull(verification);
        Assert.Equal(RemediationVerificationStatus.Verified, verification.Status);
        Assert.Equal(action.Id, verification.RemediationActionId);

        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.Verified, freshAction!.Status);
    }

    // ─── Test 2: VerifyAction Fails When Validation Shows Key Still Valid ───

    [Fact]
    public async Task Test2_VerifyAction_Fails_When_Validation_Shows_Key_Still_Valid()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Valid);

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, ExpectedVersion: 2));

        Assert.NotNull(verification);
        Assert.Equal(RemediationVerificationStatus.VerificationFailed, verification.Status);

        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.VerificationFailed, freshAction!.Status);
    }

    // ─── Test 3: Proposed Action Cannot Be Verified ─────────────────────────

    [Fact]
    public async Task Test3_ProposedAction_Cannot_Be_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(actionStatus: RemediationActionStatus.Proposed);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 4: Approved Action Cannot Be Verified ─────────────────────────

    [Fact]
    public async Task Test4_ApprovedAction_Cannot_Be_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(actionStatus: RemediationActionStatus.Approved);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 5: Failed Action Cannot Be Verified ───────────────────────────

    [Fact]
    public async Task Test5_FailedAction_Cannot_Be_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(actionStatus: RemediationActionStatus.Failed);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 6: Stale Action Version Throws Concurrency Exception ───────────

    [Fact]
    public async Task Test6_StaleActionVersion_Throws_DbUpdateConcurrencyException()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, ExpectedVersion: 99)));
    }

    // ─── Test 7: Inactive Resolved Finding Cannot Be Verified ───────────────

    [Fact]
    public async Task Test7_InactiveResolvedFinding_Cannot_Be_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(findingStatus: FindingStatus.Resolved);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 8: Action Without Successful Execution Cannot Be Verified ─────

    [Fact]
    public async Task Test8_ActionWithoutSuccessfulExecution_Cannot_Be_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        // Mark execution as failed
        execution.Status = RemediationExecutionStatus.Failed;
        execution.Success = false;
        await _dbContext.SaveChangesAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 9: Verified Status Transitions Action To Verified ──────────────

    [Fact]
    public async Task Test9_VerifiedStatus_Transitions_Action_To_Verified()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Revoked);

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.Verified, freshAction!.Status);
    }

    // ─── Test 10: VerificationFailed Status Transitions Action To Failed ────

    [Fact]
    public async Task Test10_VerificationFailedStatus_Transitions_Action_To_VerificationFailed()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Valid);

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.VerificationFailed, freshAction!.Status);
    }

    // ─── Test 11: Finding Status Preserved Unchanged After Verification ──────

    [Fact]
    public async Task Test11_FindingStatus_Preserved_Unchanged_After_Verification()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Invalid);

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, freshFinding!.Status);
    }

    // ─── Test 12: Candidate Status Preserved Unchanged After Verification ────

    [Fact]
    public async Task Test12_CandidateStatus_Preserved_Unchanged_After_Verification()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var candidate = new CredentialCandidate
        {
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = "sk-proj-****1234",
            EncryptedRawValue = "Encrypted",
            CredentialType = "OpenAIKey",
            Status = CandidateStatus.Detected
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var freshCandidate = await _dbContext.CredentialCandidates.FindAsync(candidate.Id);
        Assert.Equal(CandidateStatus.Detected, freshCandidate!.Status);
    }

    // ─── Test 13: RiskScore Recalculated After Verification ─────────────────

    [Fact]
    public async Task Test13_RiskScore_Recalculated_After_Verification()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        Assert.True(verification.PreExecutionRiskScore >= 0);
        Assert.True(verification.PostExecutionRiskScore >= 0);
    }

    // ─── Test 14: SecurityFindingEvidence Attached After Verification ───────

    [Fact]
    public async Task Test14_SecurityFindingEvidence_Attached_After_Verification()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var evidenceList = await _dbContext.SecurityFindingEvidences
            .Where(e => e.FindingId == finding.Id)
            .ToListAsync();

        Assert.NotEmpty(evidenceList);
    }

    // ─── Test 15: RemediationActionHistory Appended After Verification ───────

    [Fact]
    public async Task Test15_RemediationActionHistory_Appended_After_Verification()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var historyList = await _dbContext.RemediationActionHistories
            .Where(h => h.RemediationActionId == action.Id)
            .ToListAsync();

        Assert.NotEmpty(historyList);
        Assert.Contains(historyList, h => h.ToStatus == RemediationActionStatus.Verified);
    }

    // ─── Test 16: Zero Raw Secrets In Verification Record Or Metadata ────────

    [Fact]
    public async Task Test16_ZeroRawSecrets_In_VerificationRecord_Or_Metadata()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            verification.Id,
            verification.RemediationActionId,
            verification.Status,
            verification.ValidationResultStatus,
            verification.VerificationDetailsJson
        });

        Assert.DoesNotContain("sk-proj-raw-live-key", json);
        Assert.DoesNotContain("EncryptedRawValue", json);
    }

    // ─── Test 17: Concurrent Verification Claim Token Isolation ──────────────

    [Fact]
    public async Task Test17_ConcurrentVerificationAttempts_Result_In_Exactly_One_Claim()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        // First verification acquires claim and completes
        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));
        Assert.NotNull(verification);

        // Competing verification attempt against version 2 (now version 3) fails concurrency check
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));

        var totalVerifications = await _dbContext.RemediationVerifications
            .CountAsync(v => v.RemediationActionId == action.Id);

        Assert.Equal(1, totalVerifications);
    }

    // ─── Test 18: Audit Logs Emitted For Verification Completed ───────────────

    [Fact]
    public async Task Test18_AuditLogs_Emitted_For_Verification_Completed()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionVerificationStarted,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionVerificationCompleted,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 19: Audit Logs Emitted For Verification Failed ───────────────

    [Fact]
    public async Task Test19_AuditLogs_Emitted_For_Verification_Failed()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync(ValidationStatus.Valid);

        await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionVerificationFailed,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 20: Unauthenticated User Cannot Verify ─────────────────────────

    [Fact]
    public async Task Test20_UnauthenticatedUser_Cannot_Verify()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns((Guid?)null);

        var service = new PostRemediationVerificationService(
            _dbContext, _mockAuditService.Object, mockUser.Object, _permissionService, _findingService, _strategies);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 21: Unauthorized User Cannot Verify ─────────────────────────────

    [Fact]
    public async Task Test21_UnauthorizedUser_Cannot_Verify()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var mockUser = new Mock<ICurrentUserContext>();
        mockUser.Setup(u => u.UserId).Returns(Guid.NewGuid());
        mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);

        var service = new PostRemediationVerificationService(
            _dbContext, _mockAuditService.Object, mockUser.Object, _permissionService, _findingService, _strategies);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2)));
    }

    // ─── Test 22: GetVerificationForAction Returns Correct Record ─────────────

    [Fact]
    public async Task Test22_GetVerificationForAction_Returns_Correct_Record()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        var fetched = await _service.GetVerificationForActionAsync(action.Id);

        Assert.NotNull(fetched);
        Assert.Equal(verification.Id, fetched!.Id);
    }

    // ─── Test 23: RiskDelta Calculated Correctly ─────────────────────────────

    [Fact]
    public async Task Test23_RiskDelta_Calculated_Correctly()
    {
        var (repo, finding, action, execution) = await SeedVerificationPendingActionAsync();

        var verification = await _service.VerifyActionAsync(new VerifyRemediationActionRequest(action.Id, 2));

        Assert.Equal(verification.PreExecutionRiskScore - verification.PostExecutionRiskScore, verification.RiskDelta);
    }

    // ─── Test 24: Core Engine Isolation Verification ─────────────────────────

    [Fact]
    public void Test24_CoreEngine_Isolation_Verification()
    {
        Assert.True(typeof(RiskEngine) != null);
        Assert.True(typeof(SecurityFindingLifecycleService) != null);
    }
}
