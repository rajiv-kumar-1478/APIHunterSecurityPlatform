using System.Text.Json;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Services;

public class RiskEngineTests
{
    private readonly RiskPolicyOptions _policy;
    private readonly RiskEngine _riskEngine;

    public RiskEngineTests()
    {
        _policy = new RiskPolicyOptions
        {
            AlgorithmVersion = "v1.0",
            BaseFloorValidatedCredentialExposed = 40,
            BaseFloorUnvalidatedCredentialExposed = 20,
            WeightCredentialValid = 30,
            WeightCredentialValidInsufficientScope = 20,
            WeightProductionEnvironment = 20,
            WeightInternetFacingService = 15,
            WeightCredentialRevokedOrInvalid = -30,
            CriticalThreshold = 80,
            HighThreshold = 60,
            MediumThreshold = 35
        };

        _riskEngine = new RiskEngine(_policy);
    }

    [Fact]
    public void CalculateFindingRisk_MathematicallyConsistentTransition_ValidToRevoked()
    {
        var finding = new SecurityFinding
        {
            FindingType = FindingType.ValidatedCredentialExposed,
            Confidence = FindingConfidence.High,
            Status = FindingStatus.Open
        };

        // 1. Valid Evidence Setup: Base 40 + Valid(+30) + ProdEnv(+20) + InternetFacing(+15) = 105 -> Clamped 100
        var validEvidences = new List<SecurityFindingEvidence>
        {
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.ValidationResult,
                DiscoverySource = DiscoveryType.CredentialValidation,
                SafeEvidenceJson = "{\"provider\":\"OpenAI\",\"status\":\"Valid\"}"
            },
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.IntelligenceNode,
                DiscoverySource = DiscoveryType.AiInvestigator,
                EvidenceReference = "Environment:production",
                SafeEvidenceJson = "{\"env\":\"production\"}"
            },
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.IntelligenceNode,
                DiscoverySource = DiscoveryType.AiInvestigator,
                EvidenceReference = "Domain:api.example.com",
                SafeEvidenceJson = "{\"domain\":\"api.example.com\"}"
            }
        };

        var validResult = _riskEngine.CalculateFindingRisk(finding, validEvidences);

        Assert.Equal(100, validResult.Score);
        Assert.Equal(110, validResult.RawScore);
        Assert.Equal(RiskSeverity.Critical, validResult.Severity);
        Assert.Equal("v1.0", validResult.AlgorithmVersion);
        Assert.Contains(validResult.Factors, f => f.Code == "CREDENTIAL_VALID" && f.Weight == 30);
        Assert.Contains(validResult.Factors, f => f.Code == "MULTI_SOURCE" && f.Weight == 5);

        // 2. Transition to Revoked: Base 40 + Revoked(-30) + ProdEnv(+20) + InternetFacing(+15) + MultiSource(+5) = 50
        var revokedEvidences = new List<SecurityFindingEvidence>
        {
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.ValidationResult,
                DiscoverySource = DiscoveryType.CredentialValidation,
                SafeEvidenceJson = "{\"provider\":\"OpenAI\",\"status\":\"Revoked\"}"
            },
            validEvidences[1],
            validEvidences[2]
        };

        var revokedResult = _riskEngine.CalculateFindingRisk(finding, revokedEvidences);

        Assert.Equal(50, revokedResult.Score);
        Assert.Equal(50, revokedResult.RawScore);
        Assert.Equal(RiskSeverity.Medium, revokedResult.Severity);
        Assert.Contains(revokedResult.Factors, f => f.Code == "CREDENTIAL_REVOKED" && f.Weight == -30);

    }

    [Fact]
    public void CalculateFindingRisk_DifferentiatesValidInsufficientScopeFromFullyValid()
    {
        var finding = new SecurityFinding
        {
            FindingType = FindingType.ValidatedCredentialExposed,
            Confidence = FindingConfidence.High
        };

        var limitedScopeEvidence = new List<SecurityFindingEvidence>
        {
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.ValidationResult,
                DiscoverySource = DiscoveryType.CredentialValidation,
                SafeEvidenceJson = "{\"provider\":\"Stripe\",\"status\":\"ValidInsufficientScope\"}"
            }
        };

        var result = _riskEngine.CalculateFindingRisk(finding, limitedScopeEvidence);

        // Base 40 + ValidInsufficientScope (+20) = 60
        Assert.Equal(60, result.Score);
        Assert.Equal(RiskSeverity.High, result.Severity);
        Assert.Contains(result.Factors, f => f.Code == "CREDENTIAL_VALID_LIMITED" && f.Weight == 20 && f.Status == "ValidInsufficientScope");
    }

    [Fact]
    public void CalculateFindingRisk_BoundsScoresStrictlyBetween0And100()
    {
        var finding = new SecurityFinding { FindingType = FindingType.UnvalidatedCredentialExposed };

        // Excessive negative factors (testing lower bound clamping)
        var revokedEvidence = new List<SecurityFindingEvidence>
        {
            new SecurityFindingEvidence
            {
                EvidenceType = FindingEvidenceType.ValidationResult,
                SafeEvidenceJson = "{\"status\":\"Invalid\"}"
            }
        };

        // Unvalidated base 20 + Invalid (-30) = -10 -> Clamped to 0
        var lowResult = _riskEngine.CalculateFindingRisk(finding, revokedEvidence);
        Assert.Equal(0, lowResult.Score);
        Assert.Equal(RiskSeverity.Low, lowResult.Severity);
    }

    [Fact]
    public void MapScoreToSeverity_MapsThresholdsCorrectly()
    {
        Assert.Equal(RiskSeverity.Low, _riskEngine.MapScoreToSeverity(0));
        Assert.Equal(RiskSeverity.Low, _riskEngine.MapScoreToSeverity(34));
        Assert.Equal(RiskSeverity.Medium, _riskEngine.MapScoreToSeverity(35));
        Assert.Equal(RiskSeverity.Medium, _riskEngine.MapScoreToSeverity(59));
        Assert.Equal(RiskSeverity.High, _riskEngine.MapScoreToSeverity(60));
        Assert.Equal(RiskSeverity.High, _riskEngine.MapScoreToSeverity(79));
        Assert.Equal(RiskSeverity.Critical, _riskEngine.MapScoreToSeverity(80));
        Assert.Equal(RiskSeverity.Critical, _riskEngine.MapScoreToSeverity(100));
    }

    [Fact]
    public void CalculateRepositoryRisk_AggregatesActiveFindingsAndExcludesRemediatedAndAcceptedRisk()
    {
        var repoId = Guid.NewGuid();

        var active1 = new FindingRiskResult(80, RiskSeverity.Critical, "v1.0", 40, 80, new List<FactorContribution>(), DateTime.UtcNow);
        var active2 = new FindingRiskResult(40, RiskSeverity.Medium, "v1.0", 20, 40, new List<FactorContribution>(), DateTime.UtcNow);

        // Repo calculation: Max (80) + 0.25 * (40) = 90
        var repoResult = _riskEngine.CalculateRepositoryRisk(repoId, new[] { active1, active2 });

        Assert.Equal(90, repoResult.Score);
        Assert.Equal(RiskSeverity.Critical, repoResult.Severity);
        Assert.Equal(2, repoResult.ActiveFindingCount);

        // Verify status exclusion helper logic
        Assert.True(RiskEngine.IsActiveFindingStatus(FindingStatus.Open));
        Assert.True(RiskEngine.IsActiveFindingStatus(FindingStatus.Investigating));
        Assert.True(RiskEngine.IsActiveFindingStatus(FindingStatus.Confirmed));
        Assert.False(RiskEngine.IsActiveFindingStatus(FindingStatus.Remediated));
        Assert.False(RiskEngine.IsActiveFindingStatus(FindingStatus.AcceptedRisk));
        Assert.False(RiskEngine.IsActiveFindingStatus(FindingStatus.FalsePositive));
        Assert.False(RiskEngine.IsActiveFindingStatus(FindingStatus.Resolved));
    }

    [Fact]
    public void RiskFactorBreakdownJson_ContainsAlgorithmVersionAndValidSchema()
    {
        var finding = new SecurityFinding { FindingType = FindingType.ValidatedCredentialExposed };
        var evidence = new List<SecurityFindingEvidence>
        {
            new SecurityFindingEvidence { EvidenceType = FindingEvidenceType.ValidationResult, SafeEvidenceJson = "{\"status\":\"Valid\"}" }
        };

        var result = _riskEngine.CalculateFindingRisk(finding, evidence);
        string json = result.ToJson();

        Assert.Contains("\"algorithmVersion\":\"v1.0\"", json);
        Assert.Contains("\"finalScore\":70", json);
        Assert.Contains("\"severity\":\"High\"", json);
        Assert.Contains("CREDENTIAL_VALID", json);

        using var doc = JsonDocument.Parse(json);
        Assert.Equal("v1.0", doc.RootElement.GetProperty("algorithmVersion").GetString());
        Assert.Equal(70, doc.RootElement.GetProperty("finalScore").GetInt32());
    }
}
