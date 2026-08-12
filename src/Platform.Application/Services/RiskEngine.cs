using System.Text.Json;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record FactorContribution(string Code, string Description, int Weight, string? Status = null);

public record FindingRiskResult(
    int Score,
    RiskSeverity Severity,
    string AlgorithmVersion,
    int BaseFloor,
    int RawScore,
    List<FactorContribution> Factors,
    DateTime CalculatedAtUtc)
{
    public string ToJson()
    {
        var payload = new
        {
            algorithmVersion = AlgorithmVersion,
            calculatedAtUtc = CalculatedAtUtc,
            baseFloor = BaseFloor,
            rawScore = RawScore,
            finalScore = Score,
            severity = Severity.ToString(),
            factors = Factors
        };
        return JsonSerializer.Serialize(payload);
    }
}

public record RepositoryRiskResult(
    Guid RepositoryId,
    int Score,
    RiskSeverity Severity,
    string AlgorithmVersion,
    int ActiveFindingCount,
    string FactorBreakdownJson,
    DateTime CalculatedAtUtc);

public class RiskEngine
{
    private readonly RiskPolicyOptions _policy;

    public RiskEngine(RiskPolicyOptions policy)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    public FindingRiskResult CalculateFindingRisk(SecurityFinding finding, IEnumerable<SecurityFindingEvidence> evidences)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var evidenceList = (evidences ?? Enumerable.Empty<SecurityFindingEvidence>()).ToList();

        int baseFloor = GetBaseFloor(finding.FindingType);
        var factors = new List<FactorContribution>();

        // 1. Validation Status Factor Evaluation
        var validationEv = evidenceList.FirstOrDefault(e => e.EvidenceType == FindingEvidenceType.ValidationResult);
        if (validationEv != null && !string.IsNullOrWhiteSpace(validationEv.SafeEvidenceJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(validationEv.SafeEvidenceJson);
                if (doc.RootElement.TryGetProperty("status", out var statusProp))
                {
                    string statusStr = statusProp.GetString() ?? string.Empty;
                    if (Enum.TryParse<ValidationStatus>(statusStr, true, out var valStatus))
                    {
                        if (valStatus == ValidationStatus.Valid)
                        {
                            factors.Add(new FactorContribution("CREDENTIAL_VALID", "Credential live status verified Valid by provider", _policy.WeightCredentialValid, "Valid"));
                        }
                        else if (valStatus == ValidationStatus.ValidInsufficientScope)
                        {
                            factors.Add(new FactorContribution("CREDENTIAL_VALID_LIMITED", "Credential live status verified Valid but with limited scope", _policy.WeightCredentialValidInsufficientScope, "ValidInsufficientScope"));
                        }
                        else if (valStatus == ValidationStatus.Invalid || valStatus == ValidationStatus.Expired || valStatus == ValidationStatus.Revoked)
                        {
                            factors.Add(new FactorContribution("CREDENTIAL_REVOKED", "Credential verified Invalid, Expired, or Revoked by provider", _policy.WeightCredentialRevokedOrInvalid, valStatus.ToString()));
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // Fallback for non-JSON or malformed safe evidence string
            }
        }

        // 2. Production Environment Factor
        bool isProduction = evidenceList.Any(e => e.EvidenceReference.Contains("production", StringComparison.OrdinalIgnoreCase) || e.SafeEvidenceJson.Contains("production", StringComparison.OrdinalIgnoreCase));
        if (isProduction)
        {
            factors.Add(new FactorContribution("PRODUCTION_ENV", "Associated with production environment node or evidence", _policy.WeightProductionEnvironment));
        }

        // 3. Production Database Factor
        bool isDatabase = evidenceList.Any(e => e.EvidenceType == FindingEvidenceType.IntelligenceNode && (e.EvidenceReference.Contains("database", StringComparison.OrdinalIgnoreCase) || e.SafeEvidenceJson.Contains("database", StringComparison.OrdinalIgnoreCase)));
        if (isDatabase && isProduction)
        {
            factors.Add(new FactorContribution("PRODUCTION_DB", "Associated with database node in production environment", _policy.WeightProductionDatabase));
        }

        // 4. Internet-Facing Service Factor
        bool isInternetFacing = evidenceList.Any(e => e.EvidenceReference.Contains("domain", StringComparison.OrdinalIgnoreCase) || e.EvidenceReference.Contains("api.", StringComparison.OrdinalIgnoreCase) || e.SafeEvidenceJson.Contains("internet", StringComparison.OrdinalIgnoreCase));
        if (isInternetFacing)
        {
            factors.Add(new FactorContribution("INTERNET_FACING", "Associated with external domain or internet-facing service endpoint", _policy.WeightInternetFacingService));
        }

        // 5. Historical Commit Exposure Factor
        bool isHistorical = evidenceList.Any(e => e.EvidenceType == FindingEvidenceType.HistoricalCommit);
        if (isHistorical)
        {
            factors.Add(new FactorContribution("HISTORICAL_COMMIT", "Exposed across historical commit snapshots", _policy.WeightHistoricalCommit));
        }

        // 6. AI High Confidence Factor
        bool isAiHighConfidence = evidenceList.Any(e => e.EvidenceType == FindingEvidenceType.AiInvestigationEvidence && (finding.Confidence == FindingConfidence.High));
        if (isAiHighConfidence)
        {
            factors.Add(new FactorContribution("AI_HIGH_CONFIDENCE", "Corroborated by high-confidence AI investigation evidence", _policy.WeightAiHighConfidence));
        }

        // 7. Multi-Source Corroboration Factor
        int distinctSources = evidenceList.Select(e => e.DiscoverySource).Distinct().Count();
        if (distinctSources >= 2)
        {
            factors.Add(new FactorContribution("MULTI_SOURCE", "Corroborated by multiple independent discovery sources", _policy.WeightMultiSourceCorroboration));
        }

        int rawScore = baseFloor + factors.Sum(f => f.Weight);
        int finalScore = Math.Clamp(rawScore, 0, 100);
        RiskSeverity severity = MapScoreToSeverity(finalScore);

        return new FindingRiskResult(
            Score: finalScore,
            Severity: severity,
            AlgorithmVersion: _policy.AlgorithmVersion,
            BaseFloor: baseFloor,
            RawScore: rawScore,
            Factors: factors,
            CalculatedAtUtc: DateTime.UtcNow
        );
    }

    public RepositoryRiskResult CalculateRepositoryRisk(Guid repositoryId, IEnumerable<FindingRiskResult> activeFindingResults)
    {
        var activeList = (activeFindingResults ?? Enumerable.Empty<FindingRiskResult>()).ToList();
        if (activeList.Count == 0)
        {
            return new RepositoryRiskResult(
                RepositoryId: repositoryId,
                Score: 0,
                Severity: RiskSeverity.Low,
                AlgorithmVersion: _policy.AlgorithmVersion,
                ActiveFindingCount: 0,
                FactorBreakdownJson: JsonSerializer.Serialize(new { activeFindingCount = 0, algorithmVersion = _policy.AlgorithmVersion }),
                CalculatedAtUtc: DateTime.UtcNow
            );
        }

        int maxScore = activeList.Max(f => f.Score);
        double secondarySum = activeList.Where(f => f.Score < maxScore).Sum(f => f.Score * 0.25);
        int rawScore = (int)Math.Round(maxScore + secondarySum);
        int finalScore = Math.Clamp(rawScore, 0, 100);
        RiskSeverity severity = MapScoreToSeverity(finalScore);

        var payload = new
        {
            algorithmVersion = _policy.AlgorithmVersion,
            calculatedAtUtc = DateTime.UtcNow,
            activeFindingCount = activeList.Count,
            maxFindingScore = maxScore,
            rawRepoScore = rawScore,
            finalRepoScore = finalScore,
            severity = severity.ToString()
        };

        return new RepositoryRiskResult(
            RepositoryId: repositoryId,
            Score: finalScore,
            Severity: severity,
            AlgorithmVersion: _policy.AlgorithmVersion,
            ActiveFindingCount: activeList.Count,
            FactorBreakdownJson: JsonSerializer.Serialize(payload),
            CalculatedAtUtc: DateTime.UtcNow
        );
    }

    private int GetBaseFloor(FindingType type) => type switch
    {
        FindingType.ValidatedCredentialExposed => _policy.BaseFloorValidatedCredentialExposed,
        FindingType.ProductionServiceExposed => _policy.BaseFloorProductionServiceExposed,
        FindingType.DatabaseExposure => _policy.BaseFloorDatabaseExposure,
        FindingType.UnvalidatedCredentialExposed => _policy.BaseFloorUnvalidatedCredentialExposed,
        FindingType.HistoricalExposureDetected => _policy.BaseFloorHistoricalExposureDetected,
        FindingType.OverprivilegedCredential => _policy.BaseFloorOverprivilegedCredential,
        _ => 15
    };

    public RiskSeverity MapScoreToSeverity(int score)
    {
        if (score >= _policy.CriticalThreshold) return RiskSeverity.Critical;
        if (score >= _policy.HighThreshold) return RiskSeverity.High;
        if (score >= _policy.MediumThreshold) return RiskSeverity.Medium;
        return RiskSeverity.Low;
    }

    public static bool IsActiveFindingStatus(FindingStatus status)
    {
        return status == FindingStatus.Open ||
               status == FindingStatus.Investigating ||
               status == FindingStatus.Confirmed;
    }
}
