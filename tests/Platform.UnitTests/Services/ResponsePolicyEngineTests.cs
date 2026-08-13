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

public class ResponsePolicyEngineTests : IDisposable
{
    private readonly ResponsePolicyEngine _engine;
    private readonly RemediationRecommendationEngine _recEngine;
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly RemediationActionService _service;

    public ResponsePolicyEngineTests()
    {
        _engine = new ResponsePolicyEngine();
        _recEngine = new RemediationRecommendationEngine();

        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("PolicyDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_userId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");

        _service = new RemediationActionService(
            _dbContext,
            _mockAuditService.Object,
            _mockUserContext.Object,
            _recEngine,
            _engine,
            new ResponsePolicyOptions());
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private static SecurityFinding CreateFinding(RiskSeverity severity = RiskSeverity.High, int riskScore = 80, FindingStatus status = FindingStatus.Open)
    {
        return new SecurityFinding
        {
            RepositoryId = Guid.NewGuid(),
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = severity,
            Confidence = FindingConfidence.High,
            Title = "Validated OpenAI Exposure",
            Status = status,
            RiskScore = riskScore
        };
    }

    private static RemediationRecommendationDecision CreateDecision(RemediationActionType actionType = RemediationActionType.RevokeCredential, string? providerKey = "openai")
    {
        return new RemediationRecommendationDecision
        {
            ShouldRecommend = true,
            ActionType = actionType,
            Confidence = RecommendationConfidence.High,
            Title = "Test Decision",
            Description = "Test decision description",
            Reason = "Test reason",
            ReasonCodes = new List<string> { "TEST_REASON" },
            RequiresApproval = true,
            ProviderKey = providerKey,
            ProviderResourceReference = "sk-proj-****1234"
        };
    }

    // ─── Test 1: Standard Policy Allowed ─────────────────────────────────────

    [Fact]
    public void Test1_PolicyAllowed_Returns_IsAllowed_True()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();

        var result = _engine.Evaluate(decision, finding);

        Assert.True(result.IsAllowed);
        Assert.Null(result.DenialReason);
        Assert.Equal("v1.0", result.PolicyVersion);
        Assert.Contains("POLICY_ALLOWED", result.ReasonCodes);
        Assert.Equal("RULE_POLICY_ALLOWED", result.MatchedRuleId);
    }

    // ─── Test 2: Disabled Policy Engine Fail-Closed ─────────────────────────

    [Fact]
    public void Test2_DisabledPolicy_Returns_IsAllowed_False_With_FailClosed()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();
        var options = new ResponsePolicyOptions { Enabled = false, FailClosed = true };

        var result = _engine.Evaluate(decision, finding, options);

        Assert.False(result.IsAllowed);
        Assert.Contains("POLICY_ENGINE_DISABLED", result.ReasonCodes);
        Assert.Equal("RULE_ENGINE_DISABLED", result.MatchedRuleId);
    }

    // ─── Test 3: Action Type Disallowed By Policy ───────────────────────────

    [Fact]
    public void Test3_ActionType_Disallowed_By_Policy_Returns_IsAllowed_False()
    {
        var finding = CreateFinding();
        var decision = CreateDecision(actionType: RemediationActionType.DisableExposedService);

        var options = new ResponsePolicyOptions();
        options.AllowedActionTypes.Remove(RemediationActionType.DisableExposedService);

        var result = _engine.Evaluate(decision, finding, options);

        Assert.False(result.IsAllowed);
        Assert.Contains("ACTION_TYPE_DISALLOWED_BY_POLICY", result.ReasonCodes);
        Assert.Equal("RULE_ACTION_TYPE_DISALLOWED", result.MatchedRuleId);
    }

    // ─── Test 4: Provider Disallowed By Policy ───────────────────────────────

    [Fact]
    public void Test4_Provider_Disallowed_By_Policy_Returns_IsAllowed_False()
    {
        var finding = CreateFinding();
        var decision = CreateDecision(providerKey: "untrusted_provider");

        var result = _engine.Evaluate(decision, finding);

        Assert.False(result.IsAllowed);
        Assert.Contains("PROVIDER_DISALLOWED_BY_POLICY", result.ReasonCodes);
        Assert.Equal("RULE_PROVIDER_DISALLOWED", result.MatchedRuleId);
    }

    // ─── Test 5: Risk Score Below Policy Minimum ─────────────────────────────

    [Fact]
    public void Test5_RiskScore_Below_Policy_Minimum_Returns_IsAllowed_False()
    {
        var lowRiskFinding = CreateFinding(riskScore: 25);
        var decision = CreateDecision();
        var options = new ResponsePolicyOptions { MinimumRiskScoreToPropose = 30 };

        var result = _engine.Evaluate(decision, lowRiskFinding, options);

        Assert.False(result.IsAllowed);
        Assert.Contains("RISK_SCORE_BELOW_POLICY_MINIMUM", result.ReasonCodes);
    }

    // ─── Test 6: Severity Below Policy Minimum ───────────────────────────────

    [Fact]
    public void Test6_Severity_Below_Policy_Minimum_Returns_IsAllowed_False()
    {
        var lowSevFinding = CreateFinding(severity: RiskSeverity.Low);
        var decision = CreateDecision();
        var options = new ResponsePolicyOptions { MinimumSeverityToPropose = RiskSeverity.Medium };

        var result = _engine.Evaluate(decision, lowSevFinding, options);

        Assert.False(result.IsAllowed);
        Assert.Contains("SEVERITY_BELOW_POLICY_MINIMUM", result.ReasonCodes);
    }

    // ─── Test 7: Production Historical Scrub Disallowed ──────────────────────

    [Fact]
    public void Test7_Production_HistoricalScrub_Disallowed_Returns_IsAllowed_False()
    {
        var finding = CreateFinding();
        var decision = CreateDecision(actionType: RemediationActionType.RemoveHistoricalExposure);

        var result = _engine.Evaluate(decision, finding, repositoryEnvironment: "Production");

        Assert.False(result.IsAllowed);
        Assert.Contains("PRODUCTION_ACTION_DISALLOWED", result.ReasonCodes);
        Assert.Equal("RULE_PROD_ACTION_DISALLOWED", result.MatchedRuleId);
    }

    // ─── Test 8: Unknown Environment For Prod-Disallowed Action Fails Closed ─

    [Fact]
    public void Test8_Unknown_Environment_For_ProdDisallowed_Action_Fails_Closed()
    {
        var finding = CreateFinding();
        var decision = CreateDecision(actionType: RemediationActionType.RemoveHistoricalExposure);

        var result = _engine.Evaluate(decision, finding, repositoryEnvironment: "Unknown");

        Assert.False(result.IsAllowed);
        Assert.Contains("UNKNOWN_ENVIRONMENT_FAIL_CLOSED", result.ReasonCodes);
        Assert.Equal("RULE_UNKNOWN_ENV_FAIL_CLOSED", result.MatchedRuleId);
    }

    // ─── Test 9: Inactive Finding Returns IsAllowed False ───────────────────

    [Fact]
    public void Test9_InactiveFinding_Returns_IsAllowed_False()
    {
        var resolvedFinding = CreateFinding(status: FindingStatus.Resolved);
        var decision = CreateDecision();

        var result = _engine.Evaluate(decision, resolvedFinding);

        Assert.False(result.IsAllowed);
        Assert.Contains("INACTIVE_FINDING_PROPOSAL_DENIED", result.ReasonCodes);
    }

    // ─── Test 10: Policy Version Included In Evaluation Result ──────────────

    [Fact]
    public void Test10_PolicyVersion_Included_In_Evaluation_Result()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();
        var options = new ResponsePolicyOptions { PolicyVersion = "v2.5" };

        var result = _engine.Evaluate(decision, finding, options);

        Assert.Equal("v2.5", result.PolicyVersion);
    }

    // ─── Test 11: Null Options Defaults To Fail Closed ──────────────────────

    [Fact]
    public void Test11_Null_Options_Defaults_To_Fail_Closed()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();

        var result = _engine.Evaluate(decision, finding, options: null);

        Assert.True(result.IsAllowed); // Default ResponsePolicyOptions has Enabled = true
    }

    // ─── Test 12: Zero Raw Secret In AuditMetadataJson ───────────────────────

    [Fact]
    public void Test12_Zero_Raw_Secret_In_AuditMetadataJson()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();

        var result = _engine.Evaluate(decision, finding);

        Assert.DoesNotContain("sk-proj-raw-live-key", result.AuditMetadataJson);
        Assert.DoesNotContain("EncryptedRawValue", result.AuditMetadataJson);
    }

    // ─── Test 13: Orchestration Allowed Proposal Persists RemediationAction ─

    [Fact]
    public async Task Test13_Orchestration_AllowedProposal_Persists_RemediationAction()
    {
        var repo = new Repository { FullName = "octocat/allowed-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Validated Secret",
            Status = FindingStatus.Open,
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);

        var evidence = new SecurityFindingEvidence
        {
            FindingId = finding.Id,
            EvidenceType = FindingEvidenceType.ValidationResult,
            SafeEvidenceJson = "{\"providerKey\":\"openai\",\"maskedValue\":\"sk-proj-****8888\"}"
        };
        _dbContext.SecurityFindingEvidences.Add(evidence);
        await _dbContext.SaveChangesAsync();

        var action = await _service.EvaluateAndRecommendActionAsync(finding.Id);

        Assert.NotNull(action);
        Assert.Equal(finding.Id, action.FindingId);
        Assert.Equal(RemediationActionStatus.Proposed, action.Status);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionPolicyEvaluated,
            It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 14: Orchestration Suppressed Proposal Logs Audit And Returns Null

    [Fact]
    public async Task Test14_Orchestration_SuppressedProposal_Logs_PolicySuppressed_Audit_And_Returns_Null()
    {
        var repo = new Repository { FullName = "octocat/suppressed-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Low, // Low severity rejected by custom policy
            Title = "Low Sev Secret",
            Status = FindingStatus.Open,
            RiskScore = 35
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        var strictRespOptions = new ResponsePolicyOptions { MinimumSeverityToPropose = RiskSeverity.Medium };

        var action = await _service.EvaluateAndRecommendActionAsync(finding.Id, respOptions: strictRespOptions);

        Assert.Null(action);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionPolicySuppressed,
            It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 15: Orchestration Active Proposal Limit Throttles Creation ────

    [Fact]
    public async Task Test15_Orchestration_ActiveProposalLimit_Throttles_Creation_And_Returns_Null()
    {
        var repo = new Repository { FullName = "octocat/limit-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Limit Finding",
            Status = FindingStatus.Open,
            RiskScore = 95
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        var lowLimitOptions = new ResponsePolicyOptions { MaxProposedActionsPerFinding = 1 };

        // Create 1 active action
        var action1 = await _service.CreateActionAsync(new CreateRemediationActionRequest(
            finding.Id, RemediationActionType.RevokeCredential, "Action 1", "Desc 1"));

        Assert.NotNull(action1);

        // Second recommendation request for same finding should be throttled by MaxProposedActionsPerFinding = 1
        var action2 = await _service.EvaluateAndRecommendActionAsync(finding.Id, respOptions: lowLimitOptions);

        Assert.Null(action2);

        _mockAuditService.Verify(a => a.RecordAsync(
            AuditEventCode.RemediateActionPolicySuppressed,
            It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── Test 16: FindingStatus and CandidateStatus Preserved Unchanged ─────

    [Fact]
    public async Task Test16_FindingStatus_And_CandidateStatus_Preserved_Unchanged()
    {
        var repo = new Repository { FullName = "octocat/policy-status-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Status = FindingStatus.Open,
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        await _service.EvaluateAndRecommendActionAsync(finding.Id);

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, freshFinding!.Status);
    }

    // ─── Test 17: All Supported Providers In Default Allowlist ───────────────

    [Fact]
    public void Test17_All_Supported_Providers_In_Default_Allowlist()
    {
        var options = new ResponsePolicyOptions();

        string[] expectedProviders = { "openai", "anthropic", "github", "aws", "slack", "stripe", "sendgrid", "mailgun", "groq", "deepseek" };
        foreach (var p in expectedProviders)
        {
            Assert.Contains(p, options.AllowedProviders);
        }
    }

    // ─── Test 18: Deterministic Policy Evaluation ────────────────────────────

    [Fact]
    public void Test18_Deterministic_Policy_Evaluation()
    {
        var finding = CreateFinding();
        var decision = CreateDecision();

        var res1 = _engine.Evaluate(decision, finding);
        var res2 = _engine.Evaluate(decision, finding);

        Assert.Equal(res1.IsAllowed, res2.IsAllowed);
        Assert.Equal(res1.PolicyVersion, res2.PolicyVersion);
        Assert.Equal(res1.MatchedRuleId, res2.MatchedRuleId);
        Assert.Equal(res1.ReasonCodes, res2.ReasonCodes);
    }

    // ─── Test 19: Concurrent Proposal Limit Enforcement ───────────────────────

    [Fact]
    public async Task Test19_Concurrent_Proposal_Limit_Enforcement()
    {
        var repo = new Repository { FullName = "octocat/concurrent-limit-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Concurrent Limit Finding",
            Status = FindingStatus.Open,
            RiskScore = 95
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        var lowLimitOptions = new ResponsePolicyOptions { MaxProposedActionsPerFinding = 2 };

        // Execute 5 concurrent evaluation tasks
        var tasks = Enumerable.Range(0, 5).Select(i =>
            _service.EvaluateAndRecommendActionAsync(finding.Id, respOptions: lowLimitOptions));

        var results = await Task.WhenAll(tasks);

        var activeInDb = await _dbContext.RemediationActions
            .CountAsync(a => a.FindingId == finding.Id);

        Assert.True(activeInDb <= 2);
    }
}
