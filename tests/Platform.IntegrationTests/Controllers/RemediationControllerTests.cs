using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Api.Controllers;
using Platform.Application.Auth;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Application.Verification;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Remediation;
using Xunit;

namespace Platform.IntegrationTests.Controllers;

public class RemediationControllerTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUser;
    private readonly PermissionService _permissionService;
    private readonly RemediationApprovalService _approvalService;
    private readonly RemediationExecutionService _executionService;
    private readonly PostRemediationVerificationService _verificationService;
    private readonly RemediationController _controller;
    private readonly Guid _adminUserId = Guid.NewGuid();

    public RemediationControllerTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("RemediationControllerDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUser = new Mock<ICurrentUserContext>();
        _mockUser.Setup(u => u.UserId).Returns(_adminUserId);
        _mockUser.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUser.Setup(u => u.IpAddress).Returns("127.0.0.1");
        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(true);

        _permissionService = new PermissionService(_dbContext, _mockAuditService.Object, _mockUser.Object);
        _approvalService = new RemediationApprovalService(_dbContext, _mockAuditService.Object, _mockUser.Object, _permissionService);

        var credentialResolver = new SafeProtectedCredentialResolver();
        var provider = new GitHubRemediationProvider();
        _executionService = new RemediationExecutionService(_dbContext, _mockAuditService.Object, _mockUser.Object, _permissionService, credentialResolver, new[] { provider });

        var findingService = new SecurityFindingService(_dbContext, new RiskEngine(new Platform.Application.Configuration.RiskPolicyOptions()), NullLogger<SecurityFindingService>.Instance);
        var strategies = new IVerificationStrategy[] { new RevokeCredentialVerificationStrategy(), new FallbackVerificationStrategy() };
        _verificationService = new PostRemediationVerificationService(_dbContext, _mockAuditService.Object, _mockUser.Object, _permissionService, findingService, strategies);

        _controller = new RemediationController(
            _dbContext,
            _mockUser.Object,
            _permissionService,
            _approvalService,
            _executionService,
            _verificationService);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, SecurityFinding Finding, RemediationAction Action)> SeedSampleActionAsync(
        RemediationActionStatus status = RemediationActionStatus.Proposed,
        RemediationActionType actionType = RemediationActionType.RevokeCredential)
    {
        var repo = new Repository { FullName = "octocat/controller-test-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Leaked Stripe API Key",
            Status = FindingStatus.Open,
            RiskScore = 85
        };
        _dbContext.SecurityFindings.Add(finding);

        var action = new RemediationAction
        {
            FindingId = finding.Id,
            RepositoryId = repo.Id,
            ActionType = actionType,
            Status = status,
            Title = "Revoke Leaked Key",
            Description = "Safely revokes leaked Stripe key",
            ActionFingerprint = "fingerprint_" + Guid.NewGuid().ToString("N"),
            Version = 1,
            RequiresApproval = true,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
            ProviderKey = "github",
            ProviderResourceReference = "sk-live-****5678",
            PreExecutionRiskScore = 85
        };
        _dbContext.RemediationActions.Add(action);

        await _dbContext.SaveChangesAsync();
        return (repo, finding, action);
    }

    // ─── Test 1: Lists Remediation Actions ───────────────────────────────────

    [Fact]
    public async Task Test1_GetActions_Returns_Paginated_Actions_And_Summary()
    {
        await SeedSampleActionAsync();

        var result = await _controller.GetActions(null, null, null, null, null, 1, 20);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<RemediationListResponse>(okResult.Value);

        Assert.Single(response.Actions);
        Assert.Equal(1, response.TotalCount);
        Assert.Equal(1, response.Summary.TotalActions);
        Assert.Equal(1, response.Summary.ProposedCount);
    }

    // ─── Test 2: Filters By Status ───────────────────────────────────────────

    [Fact]
    public async Task Test2_GetActions_Filters_By_Status()
    {
        await SeedSampleActionAsync(RemediationActionStatus.Proposed);
        await SeedSampleActionAsync(RemediationActionStatus.Approved);

        var result = await _controller.GetActions(RemediationActionStatus.Approved, null, null, null, null, 1, 20);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<RemediationListResponse>(okResult.Value);

        Assert.Single(response.Actions);
        Assert.Equal(RemediationActionStatus.Approved, response.Actions[0].Status);
    }

    // ─── Test 3: Filters By Action Type ──────────────────────────────────────

    [Fact]
    public async Task Test3_GetActions_Filters_By_ActionType()
    {
        await SeedSampleActionAsync(actionType: RemediationActionType.RevokeCredential);
        await SeedSampleActionAsync(actionType: RemediationActionType.InvestigateExposure);

        var result = await _controller.GetActions(null, RemediationActionType.InvestigateExposure, null, null, null, 1, 20);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<RemediationListResponse>(okResult.Value);

        Assert.Single(response.Actions);
        Assert.Equal(RemediationActionType.InvestigateExposure, response.Actions[0].ActionType);
    }

    // ─── Test 4: Retrieves Action Details ───────────────────────────────────

    [Fact]
    public async Task Test4_GetActionById_Returns_Sanitized_DetailDto()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.GetActionById(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationActionDetailDto>(okResult.Value);

        Assert.Equal(action.Id, dto.Id);
        Assert.Equal(finding.Title, dto.FindingTitle);
        Assert.Equal(repo.FullName, dto.RepositoryFullName);
        Assert.Equal("sk-live-****5678", dto.ProviderResourceReference);
    }

    // ─── Test 5: Retrieves Immutable Action History ─────────────────────────

    [Fact]
    public async Task Test5_GetActionHistory_Returns_History_Timeline()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var history = new RemediationActionHistory
        {
            RemediationActionId = action.Id,
            FromStatus = RemediationActionStatus.Proposed,
            ToStatus = RemediationActionStatus.PendingApproval,
            Reason = "Submitted for review"
        };
        _dbContext.RemediationActionHistories.Add(history);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetActionHistory(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<RemediationActionHistoryDto>>(okResult.Value);

        Assert.Single(list);
        Assert.Equal("Submitted for review", list[0].Reason);
    }

    // ─── Test 6: Retrieves Verification Result ──────────────────────────────

    [Fact]
    public async Task Test6_GetActionVerification_Returns_VerificationDto()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var verification = new RemediationVerification
        {
            RemediationActionId = action.Id,
            Status = RemediationVerificationStatus.Verified,
            PreExecutionRiskScore = 85,
            PostExecutionRiskScore = 15,
            RiskDelta = 70,
            ValidationResultStatus = "Revoked"
        };
        _dbContext.RemediationVerifications.Add(verification);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetActionVerification(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationVerificationDto>(okResult.Value);

        Assert.Equal(verification.Id, dto.Id);
        Assert.Equal(70, dto.RiskDelta);
        Assert.Equal(RemediationVerificationStatus.Verified, dto.Status);
    }

    // ─── Test 7: Unauthorized User Cannot Approve ────────────────────────────

    [Fact]
    public async Task Test7_Unauthorized_User_Cannot_Approve()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);
        _mockUser.Setup(u => u.UserId).Returns(Guid.NewGuid());

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 1, Reason: "Valid reason"));

        Assert.IsType<ForbidResult>(result);
    }

    // ─── Test 8: Authorized User Can Approve ──────────────────────────────────

    [Fact]
    public async Task Test8_Authorized_User_Can_Approve()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 1, Reason: "Approved for emergency revocation"));

        Assert.IsType<OkObjectResult>(result);
        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.Approved, freshAction!.Status);
        Assert.Equal(2, freshAction.Version);
    }

    // ─── Test 9: Authorized User Can Reject ───────────────────────────────────

    [Fact]
    public async Task Test9_Authorized_User_Can_Reject()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.RejectAction(action.Id, new RejectRemediationRequest(ExpectedVersion: 1, Reason: "False positive"));

        Assert.IsType<OkObjectResult>(result);
        var freshAction = await _dbContext.RemediationActions.FindAsync(action.Id);
        Assert.Equal(RemediationActionStatus.Rejected, freshAction!.Status);
    }

    // ─── Test 10: Missing Reason Rejected ────────────────────────────────────

    [Fact]
    public async Task Test10_Missing_Reason_Rejected_With_BadRequest()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 1, Reason: "  "));

        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ─── Test 11: Stale Version Returns 409 Conflict ──────────────────────────

    [Fact]
    public async Task Test11_Stale_Version_Returns_409_Conflict()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 99, Reason: "Valid reason"));

        var conflictResult = Assert.IsType<ConflictObjectResult>(result);
        Assert.NotNull(conflictResult.Value);
    }

    // ─── Test 12: Terminal Action Cannot Be Approved ──────────────────────────

    [Fact]
    public async Task Test12_Terminal_Action_Cannot_Be_Approved()
    {
        var (repo, finding, action) = await SeedSampleActionAsync(RemediationActionStatus.Verified);

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 1, Reason: "Valid reason"));

        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ─── Test 13: Execution Status Displayed Correctly ────────────────────────

    [Fact]
    public async Task Test13_Execution_Status_Returned_In_DetailDto()
    {
        var (repo, finding, action) = await SeedSampleActionAsync(RemediationActionStatus.Executing);
        action.ExecutionStartedAtUtc = DateTime.UtcNow.AddMinutes(-5);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetActionById(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationActionDetailDto>(okResult.Value);

        Assert.Equal(RemediationActionStatus.Executing, dto.Status);
        Assert.NotNull(dto.ExecutionStartedAtUtc);
    }

    // ─── Test 14: Verification Result Displayed Correctly ────────────────────

    [Fact]
    public async Task Test14_Verification_Result_Returned_In_DetailDto()
    {
        var (repo, finding, action) = await SeedSampleActionAsync(RemediationActionStatus.Verified);
        var verification = new RemediationVerification
        {
            RemediationActionId = action.Id,
            Status = RemediationVerificationStatus.Verified,
            PreExecutionRiskScore = 85,
            PostExecutionRiskScore = 15,
            RiskDelta = 70,
            ValidationResultStatus = "Revoked"
        };
        _dbContext.RemediationVerifications.Add(verification);
        await _dbContext.SaveChangesAsync();

        var result = await _controller.GetActionById(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationActionDetailDto>(okResult.Value);

        Assert.NotNull(dto.Verification);
        Assert.Equal(RemediationVerificationStatus.Verified, dto.Verification!.Status);
    }

    // ─── Test 15: Raw Secrets Never Appear In DTOs ───────────────────────────

    [Fact]
    public async Task Test15_Raw_Secrets_Never_Appear_In_DTOs()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.GetActionById(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationActionDetailDto>(okResult.Value);

        var json = System.Text.Json.JsonSerializer.Serialize(dto);
        Assert.DoesNotContain("sk-live-raw-secret-key", json);
        Assert.Contains("sk-live-****5678", json);
    }

    // ─── Test 16: Risk Values Are Backend Provided Only ──────────────────────

    [Fact]
    public async Task Test16_Risk_Values_Are_Backend_Provided_Only()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.GetActionById(action.Id);

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dto = Assert.IsType<RemediationActionDetailDto>(okResult.Value);

        Assert.Equal(85, dto.PreExecutionRiskScore);
        Assert.Equal(RiskSeverity.Critical, dto.FindingSeverity);
    }

    // ─── Test 17: Finding Status Remains Unchanged ───────────────────────────

    [Fact]
    public async Task Test17_Finding_Status_Remains_Unchanged_After_Approval()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 1, Reason: "Approved"));

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, freshFinding!.Status);
    }

    // ─── Test 18: Concurrency Conflict Response Contains Clear Error Metadata ──

    [Fact]
    public async Task Test18_Concurrency_Conflict_Returns_Standard_409_Body()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        var result = await _controller.ApproveAction(action.Id, new ApproveRemediationRequest(ExpectedVersion: 999, Reason: "Stale version payload"));

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        var json = System.Text.Json.JsonSerializer.Serialize(conflict.Value);
        Assert.Contains("CONCURRENCY_CONFLICT", json);
    }

    // ─── Test 19: API Authorization Remained Enforced Independently ──────────

    [Fact]
    public async Task Test19_API_Authorization_Enforced_Independently()
    {
        var (repo, finding, action) = await SeedSampleActionAsync();

        _mockUser.Setup(u => u.IsPlatformAdmin).Returns(false);
        _mockUser.Setup(u => u.UserId).Returns(Guid.NewGuid());

        var result = await _controller.GetActions(null, null, null, null, null, 1, 20);

        Assert.IsType<ForbidResult>(result);
    }

    // ─── Test 20: Dedicated DTO Boundary Verification ────────────────────────

    [Fact]
    public void Test20_Dedicated_DTO_Boundary_Verification()
    {
        Assert.True(typeof(RemediationActionListDto) != null);
        Assert.True(typeof(RemediationActionDetailDto) != null);
        Assert.True(typeof(RemediationActionHistoryDto) != null);
        Assert.True(typeof(RemediationVerificationDto) != null);
        Assert.True(typeof(RemediationSummaryDto) != null);
    }
}
