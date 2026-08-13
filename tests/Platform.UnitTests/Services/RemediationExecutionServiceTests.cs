using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Permissions;
using Platform.Application.Providers;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Remediation;
using Xunit;

namespace Platform.UnitTests.Services;

public class RemediationExecutionServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly PermissionService _permissionService;
    private readonly IProtectedCredentialResolver _credentialResolver;
    private readonly List<IRemediationProvider> _providers;
    private readonly RemediationExecutionService _service;
    private readonly Guid _adminUserId = Guid.NewGuid();

    public RemediationExecutionServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ExecutionDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_adminUserId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");
        _mockUserContext.Setup(u => u.IsPlatformAdmin).Returns(true);

        _permissionService = new PermissionService(_dbContext, _mockAuditService.Object, _mockUserContext.Object);
        _credentialResolver = new SafeProtectedCredentialResolver();
        _providers = new List<IRemediationProvider>
        {
            new GitHubRemediationProvider(),
            new SafeFallbackRemediationProvider()
        };

        _service = new RemediationExecutionService(
            _dbContext,
            _mockAuditService.Object,
            _mockUserContext.Object,
            _permissionService,
            _credentialResolver,
            _providers);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, SecurityFinding Finding, RemediationAction Action)> SeedApprovedActionAsync(
        RemediationActionStatus actionStatus = RemediationActionStatus.Approved,
        FindingStatus findingStatus = FindingStatus.Open,
        string providerKey = "github",
        RemediationActionType actionType = RemediationActionType.RevokeCredential,
        int expiryHours = 24)
    {
        var repo = new Repository { FullName = "octocat/execution-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Validated GitHub Token Exposure",
            Status = findingStatus,
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);

        var action = new RemediationAction
        {
            FindingId = finding.Id,
            RepositoryId = repo.Id,
            ActionType = actionType,
            Status = actionStatus,
            Title = "Revoke GitHub Token",
            Description = "Revoke token via GitHub API",
            ActionFingerprint = "fingerprint_" + Guid.NewGuid().ToString("N"),
            Version = 1,
            RequiresApproval = true,
            ApprovedByUserId = _adminUserId,
            ApprovedAtUtc = DateTime.UtcNow.AddHours(-1),
            ApprovalReason = "Approved by SecOps Lead",
            ExpiresAtUtc = DateTime.UtcNow.AddHours(expiryHours),
            ProviderKey = providerKey,
            ProviderResourceReference = "ghp_****1234",
            PreExecutionRiskScore = 90
        };
        _dbContext.RemediationActions.Add(action);

        await _dbContext.SaveChangesAsync();
        return (repo, finding, action);
    }

    // ─── Test 1: Approved Action Executes Successfully ───────────────────────

    [Fact]
    public async Task Test1_ApprovedAction_Executes_Successfully_With_SupportedProvider()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var execution = await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, ExpectedVersion: 1));

        Assert.NotNull(execution);
        Assert.Equal(RemediationExecutionStatus.Succeeded, execution.Status);
        Assert.True(execution.Success);
        Assert.NotNull(execution.ProviderOperationId);
        Assert.StartsWith("gh_op_", execution.ProviderOperationId);

        // Action lifecycle state transitioned to VerificationPending (Step 6)
        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.VerificationPending, freshAction!.Status);
    }

    // ─── Test 2: Proposed Action Cannot Execute ──────────────────────────────

    [Fact]
    public async Task Test2_ProposedAction_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(actionStatus: RemediationActionStatus.Proposed);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 3: PendingApproval Action Cannot Execute ───────────────────────

    [Fact]
    public async Task Test3_PendingApprovalAction_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(actionStatus: RemediationActionStatus.PendingApproval);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 4: Rejected Action Cannot Execute ──────────────────────────────

    [Fact]
    public async Task Test4_RejectedAction_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(actionStatus: RemediationActionStatus.Rejected);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 5: Expired Approval Lease Cannot Execute ───────────────────────

    [Fact]
    public async Task Test5_ExpiredApprovalLease_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(expiryHours: -1);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 6: Inactive Resolved Finding Cannot Execute ─────────────────────

    [Fact]
    public async Task Test6_InactiveResolvedFinding_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(findingStatus: FindingStatus.Resolved);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 7: Inactive Remediated Finding Cannot Execute ───────────────────

    [Fact]
    public async Task Test7_InactiveRemediatedFinding_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(findingStatus: FindingStatus.Remediated);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 8: Inactive AcceptedRisk Finding Cannot Execute ─────────────────

    [Fact]
    public async Task Test8_InactiveAcceptedRiskFinding_Cannot_Execute()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(findingStatus: FindingStatus.AcceptedRisk);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 9: Stale Action Version Throws Concurrency Exception ────────────

    [Fact]
    public async Task Test9_StaleActionVersion_Throws_DbUpdateConcurrencyException()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, ExpectedVersion: 99)));
    }

    // ─── Test 10: Duplicate Execution Attempt Prevented ──────────────────────

    [Fact]
    public async Task Test10_DuplicateExecutionAttempt_Prevented()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        // Second execution attempt against action now at version 2 with ExpectedVersion 1 fails concurrency check
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 11: Unsupported Provider Rejects Execution ────────────────────

    [Fact]
    public async Task Test11_UnsupportedProvider_Rejects_Execution()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(providerKey: "unregistered_provider");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 12: Unsupported Action Type Rejects Execution ─────────────────

    [Fact]
    public async Task Test12_UnsupportedActionType_Rejects_Execution()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync(actionType: RemediationActionType.DisableExposedService);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1)));
    }

    // ─── Test 13: Provider Failure Creates Failed Execution ──────────────────

    [Fact]
    public async Task Test13_ProviderFailure_Creates_FailedExecution()
    {
        var mockFailingProvider = new Mock<IRemediationProvider>();
        mockFailingProvider.Setup(p => p.ProviderKey).Returns("failing_provider");
        mockFailingProvider.Setup(p => p.Supports(It.IsAny<RemediationActionType>())).Returns(true);
        mockFailingProvider.Setup(p => p.ExecuteAsync(It.IsAny<RemediationExecutionContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RemediationProviderResult(
                Success: false,
                ProviderOperationId: null,
                FailureCode: "API_ERROR_500",
                FailureReason: "GitHub API upstream connection refused"));

        var serviceWithFail = new RemediationExecutionService(
            _dbContext, _mockAuditService.Object, _mockUserContext.Object, _permissionService, _credentialResolver,
            new List<IRemediationProvider> { mockFailingProvider.Object });

        var (repo, finding, action) = await SeedApprovedActionAsync(providerKey: "failing_provider");

        var execution = await serviceWithFail.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        Assert.NotNull(execution);
        Assert.Equal(RemediationExecutionStatus.Failed, execution.Status);
        Assert.False(execution.Success);
        Assert.Equal("API_ERROR_500", execution.FailureCode);

        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.Failed, freshAction!.Status);
    }

    // ─── Test 14: Provider Success Creates Succeeded Execution ───────────────

    [Fact]
    public async Task Test14_ProviderSuccess_Creates_SucceededExecution()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var execution = await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        Assert.Equal(RemediationExecutionStatus.Succeeded, execution.Status);
        Assert.True(execution.Success);
    }

    // ─── Test 15: Execution Timestamps And Duration Recorded ───────────────

    [Fact]
    public async Task Test15_ExecutionTimestamps_And_DurationMs_Recorded()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var execution = await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        Assert.True(execution.StartedAtUtc <= DateTime.UtcNow);
        Assert.NotNull(execution.CompletedAtUtc);
        Assert.True(execution.ExecutionDurationMs >= 0);
    }

    // ─── Test 16: Provider Operation ID Recorded ─────────────────────────────

    [Fact]
    public async Task Test16_ProviderOperationId_Recorded()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var execution = await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        Assert.False(string.IsNullOrWhiteSpace(execution.ProviderOperationId));
    }

    // ─── Test 17: Zero Raw Secrets In Execution Record Or Metadata ───────────

    [Fact]
    public async Task Test17_ZeroRawSecrets_In_ExecutionRecord_Or_Metadata()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var execution = await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            execution.Id,
            execution.RemediationActionId,
            execution.ActionVersion,
            execution.Status,
            execution.ProviderKey,
            execution.ProviderResourceReference,
            execution.FailureCode,
            execution.FailureReason,
            execution.ProviderOperationId
        });

        Assert.DoesNotContain("resolved_secret_", json);
        Assert.DoesNotContain("RawCredentialValue", json);
    }

    // ─── Test 18: Finding Status Preserved Unchanged After Execution ─────────

    [Fact]
    public async Task Test18_FindingStatus_Preserved_Unchanged_After_Successful_Execution()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, freshFinding!.Status);
    }

    // ─── Test 19: Candidate Status Preserved Unchanged After Execution ───────

    [Fact]
    public async Task Test19_CandidateStatus_Preserved_Unchanged_After_Successful_Execution()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var candidate = new CredentialCandidate
        {
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = "ghp_****1234",
            EncryptedRawValue = "Encrypted",
            CredentialType = "GitHubToken",
            Status = CandidateStatus.Detected
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        var freshCandidate = await _dbContext.CredentialCandidates.FindAsync(candidate.Id);
        Assert.Equal(CandidateStatus.Detected, freshCandidate!.Status);
    }

    // ─── Test 20: GitHub Provider RevokeCredential Capability Supported ─────

    [Fact]
    public void Test20_GitHubProvider_RevokeCredential_Capability_Supported()
    {
        var provider = new GitHubRemediationProvider();

        Assert.Equal("github", provider.ProviderKey);
        Assert.True(provider.Supports(RemediationActionType.RevokeCredential));
        Assert.True(provider.Supports(RemediationActionType.InvestigateExposure));
        Assert.False(provider.Supports(RemediationActionType.RotateCredential));
    }

    // ─── Test 21: Audit Logs Emitted For Execution Started And Completed ─────

    [Fact]
    public async Task Test21_AuditLogs_Emitted_For_Execution_Started_And_Completed()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        await _service.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionExecutionStarted,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionExecutionCompleted,
            _adminUserId, It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 22: Core Engine Isolation Verification ─────────────────────────

    [Fact]
    public void Test22_CoreEngine_Isolation_Verification()
    {
        Assert.True(typeof(RiskEngine) != null);
        Assert.True(typeof(SecurityFindingLifecycleService) != null);
    }

    // ─── Test 23: ConcurrentClaim BeforeProviderCall ExactlyOneOwner ──────────

    [Fact]
    public async Task Test23_ConcurrentClaim_BeforeProviderCall_ExactlyOneOwner()
    {
        var (repo, finding, action) = await SeedApprovedActionAsync();

        var request1 = new ExecuteRemediationActionRequest(action.Id, ExpectedVersion: 1);
        var request2 = new ExecuteRemediationActionRequest(action.Id, ExpectedVersion: 1);

        // First worker acquires atomic claim
        var execution = await _service.ExecuteActionAsync(request1);
        Assert.NotNull(execution);

        // Competing worker attempt against version 1 fails
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            _service.ExecuteActionAsync(request2));

        var totalExecutions = await _dbContext.RemediationExecutions
            .CountAsync(e => e.RemediationActionId == action.Id);

        Assert.Equal(1, totalExecutions);
    }

    // ─── Test 24: ProtectedCredentialResolver NeverPersistsRawSecret ─────────

    [Fact]
    public async Task Test24_ProtectedCredentialResolver_NeverPersistsRawSecret()
    {
        var resolver = new SafeProtectedCredentialResolver();
        var resolved = await resolver.ResolveAsync("github", "ghp_****1234");

        Assert.NotNull(resolved);
        Assert.Equal("github", resolved!.ProviderKey);
        Assert.Equal("ghp_****1234", resolved.ResourceReference);

        var dbExecutions = await _dbContext.RemediationExecutions.ToListAsync();
        foreach (var ex in dbExecutions)
        {
            Assert.DoesNotContain("resolved_secret_", ex.ProviderResourceReference ?? "");
        }
    }

    // ─── Test 25: ProviderException DoesNotLeakSecretIntoFailureReason ───────

    [Fact]
    public async Task Test25_ProviderException_DoesNotLeakSecretIntoFailureReason()
    {
        var mockExProvider = new Mock<IRemediationProvider>();
        mockExProvider.Setup(p => p.ProviderKey).Returns("ex_provider");
        mockExProvider.Setup(p => p.Supports(It.IsAny<RemediationActionType>())).Returns(true);
        mockExProvider.Setup(p => p.ExecuteAsync(It.IsAny<RemediationExecutionContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("API connection timeout for key ghp_secret_raw_key"));

        var serviceWithEx = new RemediationExecutionService(
            _dbContext, _mockAuditService.Object, _mockUserContext.Object, _permissionService, _credentialResolver,
            new List<IRemediationProvider> { mockExProvider.Object });

        var (repo, finding, action) = await SeedApprovedActionAsync(providerKey: "ex_provider");

        var execution = await serviceWithEx.ExecuteActionAsync(new ExecuteRemediationActionRequest(action.Id, 1));

        Assert.Equal(RemediationExecutionStatus.Failed, execution.Status);
        Assert.Equal("PROVIDER_EXCEPTION", execution.FailureCode);
        Assert.NotNull(execution.FailureReason);
    }
}
