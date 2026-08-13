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

public class RemediationRecommendationEngineTests : IDisposable
{
    private readonly RemediationRecommendationEngine _engine;
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ICurrentUserContext> _mockUserContext;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly RemediationActionService _service;

    public RemediationRecommendationEngineTests()
    {
        _engine = new RemediationRecommendationEngine();

        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("RecommendationDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockAuditService = new Mock<IAuditService>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(_userId);
        _mockUserContext.Setup(u => u.SessionId).Returns(Guid.NewGuid().ToString("N"));
        _mockUserContext.Setup(u => u.IpAddress).Returns("127.0.0.1");

        _service = new RemediationActionService(_dbContext, _mockAuditService.Object, _mockUserContext.Object, _engine, new ResponsePolicyEngine(), new ResponsePolicyOptions());
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private static SecurityFinding CreateFinding(FindingType type, int riskScore = 80, FindingStatus status = FindingStatus.Open)
    {
        return new SecurityFinding
        {
            RepositoryId = Guid.NewGuid(),
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = type,
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            Title = $"Finding {type}",
            Description = "Test finding",
            Status = status,
            RiskScore = riskScore
        };
    }

    // ─── Test 1: ValidatedCredentialExposed -> RevokeCredential ──────────────

    [Fact]
    public void Test1_ValidatedCredentialExposed_Recommends_RevokeCredential()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.RevokeCredential, decision.ActionType);
        Assert.Equal(RecommendationConfidence.High, decision.Confidence);
        Assert.True(decision.RequiresApproval);
        Assert.Contains("VALIDATED_SECRET_EXPOSED", decision.ReasonCodes);
    }

    // ─── Test 2: RevokedCredentialExposed -> ShouldRecommend = False ─────────

    [Fact]
    public void Test2_RevokedCredentialExposed_Returns_ShouldRecommend_False()
    {
        var finding = CreateFinding(FindingType.RevokedCredentialExposed, 90);
        var decision = _engine.Evaluate(finding);

        Assert.False(decision.ShouldRecommend);
        Assert.Contains("CREDENTIAL_ALREADY_REVOKED", decision.ReasonCodes);
    }

    // ─── Test 3: ExpiredCredentialExposed -> InvestigateExposure ─────────────

    [Fact]
    public void Test3_ExpiredCredentialExposed_Recommends_InvestigateExposure()
    {
        var finding = CreateFinding(FindingType.ExpiredCredentialExposed, 60);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.InvestigateExposure, decision.ActionType);
        Assert.Contains("CREDENTIAL_EXPIRED", decision.ReasonCodes);
    }

    // ─── Test 4: OverprivilegedCredential -> RestrictCredentialScope ─────────

    [Fact]
    public void Test4_OverprivilegedCredential_Recommends_RestrictCredentialScope()
    {
        var finding = CreateFinding(FindingType.OverprivilegedCredential, 85);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.RestrictCredentialScope, decision.ActionType);
        Assert.Equal(RecommendationConfidence.High, decision.Confidence);
        Assert.Contains("OVERPRIVILEGED_SCOPE", decision.ReasonCodes);
    }

    // ─── Test 5: ProductionServiceExposed -> DisableExposedService ───────────

    [Fact]
    public void Test5_ProductionServiceExposed_Recommends_DisableExposedService()
    {
        var finding = CreateFinding(FindingType.ProductionServiceExposed, 95);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.DisableExposedService, decision.ActionType);
        Assert.Equal(RecommendationConfidence.High, decision.Confidence);
        Assert.Contains("PRODUCTION_SERVICE_EXPOSED", decision.ReasonCodes);
    }

    // ─── Test 6: HistoricalExposureDetected -> RemoveHistoricalExposure ─────

    [Fact]
    public void Test6_HistoricalExposureDetected_Recommends_RemoveHistoricalExposure()
    {
        var finding = CreateFinding(FindingType.HistoricalExposureDetected, 70);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.RemoveHistoricalExposure, decision.ActionType);
        Assert.Contains("HISTORICAL_COMMIT_EXPOSURE", decision.ReasonCodes);
    }

    // ─── Test 7: UnvalidatedCredentialExposed -> InvestigateExposure ────────

    [Fact]
    public void Test7_UnvalidatedCredentialExposed_Recommends_InvestigateExposure()
    {
        var finding = CreateFinding(FindingType.UnvalidatedCredentialExposed, 50);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.InvestigateExposure, decision.ActionType);
        Assert.Contains("PROVIDER_CONTEXT_INSUFFICIENT", decision.ReasonCodes);
    }

    // ─── Test 8: DatabaseExposure -> RotateCredential ───────────────────────

    [Fact]
    public void Test8_DatabaseExposure_Recommends_RotateCredential()
    {
        var finding = CreateFinding(FindingType.DatabaseExposure, 88);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.ShouldRecommend);
        Assert.Equal(RemediationActionType.RotateCredential, decision.ActionType);
        Assert.Equal(RecommendationConfidence.High, decision.Confidence);
        Assert.Contains("DATABASE_CREDENTIAL_EXPOSED", decision.ReasonCodes);
    }

    // ─── Test 9: Resolved/Inactive Finding -> ShouldRecommend = False ───────

    [Fact]
    public void Test9_ResolvedFinding_Returns_ShouldRecommend_False()
    {
        var resolvedFinding = CreateFinding(FindingType.ValidatedCredentialExposed, 90, FindingStatus.Resolved);
        var decision = _engine.Evaluate(resolvedFinding);

        Assert.False(decision.ShouldRecommend);
        Assert.Contains("FINDING_INACTIVE_OR_RESOLVED", decision.ReasonCodes);
    }

    // ─── Test 10: RiskScore Below Minimum -> ShouldRecommend = False ─────────

    [Fact]
    public void Test10_RiskScore_Below_Minimum_Returns_ShouldRecommend_False()
    {
        var lowRiskFinding = CreateFinding(FindingType.ValidatedCredentialExposed, riskScore: 20);
        var options = new RemediationRecommendationPolicyOptions { MinimumRiskScoreForRecommendation = 30 };

        var decision = _engine.Evaluate(lowRiskFinding, options: options);

        Assert.False(decision.ShouldRecommend);
        Assert.Contains("RISK_BELOW_RECOMMENDATION_THRESHOLD", decision.ReasonCodes);
    }

    // ─── Test 11: Engine Disabled Option -> ShouldRecommend = False ─────────

    [Fact]
    public void Test11_EngineDisabled_Option_Returns_ShouldRecommend_False()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);
        var options = new RemediationRecommendationPolicyOptions { EngineEnabled = false };

        var decision = _engine.Evaluate(finding, options: options);

        Assert.False(decision.ShouldRecommend);
        Assert.Contains("ENGINE_DISABLED", decision.ReasonCodes);
    }

    // ─── Test 12: RequiresApproval Always True ───────────────────────────────

    [Fact]
    public void Test12_RequiresApproval_Always_True_In_Decision()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);
        var decision = _engine.Evaluate(finding);

        Assert.True(decision.RequiresApproval);
    }

    // ─── Test 13: Deterministic Evaluation Returns Identical Decision ───────

    [Fact]
    public void Test13_Deterministic_Evaluation_Returns_Identical_Decision()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);

        var decision1 = _engine.Evaluate(finding);
        var decision2 = _engine.Evaluate(finding);

        Assert.Equal(decision1.ActionType, decision2.ActionType);
        Assert.Equal(decision1.Confidence, decision2.Confidence);
        Assert.Equal(decision1.ReasonCodes, decision2.ReasonCodes);
        Assert.Equal(decision1.ExplanationJson, decision2.ExplanationJson);
    }

    // ─── Test 14: Extracts Provider Context From Evidence ───────────────────

    [Fact]
    public void Test14_ProviderKey_And_MaskedReference_Extracted_From_Evidence()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);
        var evidences = new[]
        {
            new SecurityFindingEvidence
            {
                FindingId = finding.Id,
                EvidenceType = FindingEvidenceType.ValidationResult,
                SafeEvidenceJson = "{\"providerKey\":\"openai\",\"maskedValue\":\"sk-proj-****1234\"}"
            }
        };

        var decision = _engine.Evaluate(finding, evidences);

        Assert.Equal("openai", decision.ProviderKey);
        Assert.Equal("sk-proj-****1234", decision.ProviderResourceReference);
    }

    // ─── Test 15: Zero Raw Secret In Decision ExplanationJson ───────────────

    [Fact]
    public void Test15_RawSecrets_Absence_In_Decision_ExplanationJson()
    {
        var finding = CreateFinding(FindingType.ValidatedCredentialExposed, 90);
        var decision = _engine.Evaluate(finding);

        Assert.DoesNotContain("sk-proj-raw-live-key", decision.ExplanationJson);
        Assert.DoesNotContain("EncryptedRawValue", decision.ExplanationJson);
    }

    // ─── Test 16: Orchestration EvaluateAndRecommendActionAsync Persists Action

    [Fact]
    public async Task Test16_Orchestration_EvaluateAndRecommendActionAsync_Persists_Proposed_RemediationAction()
    {
        var repo = new Repository { FullName = "octocat/recommendation-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Title = "Validated OpenAI Exposure",
            Status = FindingStatus.Open,
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);

        var evidence = new SecurityFindingEvidence
        {
            FindingId = finding.Id,
            EvidenceType = FindingEvidenceType.ValidationResult,
            SafeEvidenceJson = "{\"providerKey\":\"openai\",\"maskedValue\":\"sk-proj-****9999\"}"
        };
        _dbContext.SecurityFindingEvidences.Add(evidence);
        await _dbContext.SaveChangesAsync();

        var action = await _service.EvaluateAndRecommendActionAsync(finding.Id);

        Assert.NotNull(action);
        Assert.Equal(finding.Id, action.FindingId);
        Assert.Equal(RemediationActionType.RevokeCredential, action.ActionType);
        Assert.Equal(RemediationActionStatus.Proposed, action.Status);
        Assert.True(action.RequiresApproval);
        Assert.Equal("openai", action.ProviderKey);
        Assert.Equal("sk-proj-****9999", action.ProviderResourceReference);
    }

    // ─── Test 17: Orchestration Deduplicates Duplicate Evaluation Runs ───────

    [Fact]
    public async Task Test17_Orchestration_Deduplicates_Duplicate_Evaluation_Runs()
    {
        var repo = new Repository { FullName = "octocat/dedup-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.OverprivilegedCredential,
            Status = FindingStatus.Open,
            RiskScore = 85
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        var action1 = await _service.EvaluateAndRecommendActionAsync(finding.Id);
        var action2 = await _service.EvaluateAndRecommendActionAsync(finding.Id);

        Assert.NotNull(action1);
        Assert.NotNull(action2);
        Assert.Equal(action1.Id, action2.Id);
    }

    // ─── Test 18: FindingStatus and CandidateStatus Preserved Unchanged ─────

    [Fact]
    public async Task Test18_FindingStatus_And_CandidateStatus_Preserved_Unchanged()
    {
        var repo = new Repository { FullName = "octocat/status-check-repo" };
        _dbContext.Repositories.Add(repo);

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Status = FindingStatus.Open,
            RiskScore = 95
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        await _service.EvaluateAndRecommendActionAsync(finding.Id);

        var freshFinding = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, freshFinding!.Status);
    }
}
