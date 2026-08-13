using System.Text.Json;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Pure, deterministic decision engine for evaluating security findings and producing explainable remediation proposals.
/// STRICT BOUNDARY: Pure in-memory logic. Zero DB persistence, zero provider network calls, zero raw secret decryption, zero AI decision-making.
/// </summary>
public class RemediationRecommendationEngine
{
    private static readonly HashSet<FindingStatus> InactiveFindingStatuses = new()
    {
        FindingStatus.Resolved,
        FindingStatus.Remediated,
        FindingStatus.FalsePositive,
        FindingStatus.AcceptedRisk
    };

    public RemediationRecommendationDecision Evaluate(
        SecurityFinding finding,
        IEnumerable<SecurityFindingEvidence>? evidences = null,
        RemediationRecommendationPolicyOptions? options = null)
    {
        if (finding == null) throw new ArgumentNullException(nameof(finding));
        options ??= new RemediationRecommendationPolicyOptions();
        evidences ??= Array.Empty<SecurityFindingEvidence>();

        // 1. Engine Enabled Check
        if (!options.EngineEnabled)
        {
            return CreateNegativeDecision("ENGINE_DISABLED", "Remediation recommendation engine is disabled in system configuration.");
        }

        // 2. Finding Status Inactive Check
        if (InactiveFindingStatuses.Contains(finding.Status))
        {
            return CreateNegativeDecision("FINDING_INACTIVE_OR_RESOLVED", $"Finding status '{finding.Status}' requires no remediation recommendation.");
        }

        // 3. Already Revoked Credential Check
        if (finding.FindingType == FindingType.RevokedCredentialExposed)
        {
            return CreateNegativeDecision("CREDENTIAL_ALREADY_REVOKED", "Credential is confirmed revoked at provider. No remediation action required.");
        }

        // 4. Minimum Risk Score Check (Low-risk rule alignment)
        if (finding.RiskScore < options.MinimumRiskScoreForRecommendation)
        {
            return CreateNegativeDecision(
                "RISK_BELOW_RECOMMENDATION_THRESHOLD",
                $"Finding risk score {finding.RiskScore} is below minimum recommendation threshold of {options.MinimumRiskScoreForRecommendation}.");
        }

        // 5. Extract Provider Key & Resource Reference (Masked values only)
        var (providerKey, resourceRef) = ExtractProviderContext(evidences);

        // 6. Policy Matrix Evaluation
        var decision = EvaluatePolicyMatrix(finding, providerKey, resourceRef, options);

        decision.ProviderKey = providerKey;
        decision.ProviderResourceReference = resourceRef;
        decision.RequiresApproval = true;
        decision.ExplanationJson = JsonSerializer.Serialize(new
        {
            findingId = finding.Id,
            findingType = finding.FindingType.ToString(),
            riskScore = finding.RiskScore,
            reasonCodes = decision.ReasonCodes,
            actionType = decision.ActionType.ToString()
        });

        return decision;
    }

    private static (string? ProviderKey, string? ResourceRef) ExtractProviderContext(IEnumerable<SecurityFindingEvidence> evidences)
    {
        string? providerKey = null;
        string? resourceRef = null;

        foreach (var ev in evidences)
        {
            if (string.IsNullOrWhiteSpace(ev.SafeEvidenceJson) || ev.SafeEvidenceJson == "{}") continue;

            try
            {
                using var doc = JsonDocument.Parse(ev.SafeEvidenceJson);
                var root = doc.RootElement;

                if (root.TryGetProperty("providerKey", out var pKey) && pKey.ValueKind == JsonValueKind.String)
                {
                    providerKey ??= pKey.GetString();
                }
                if (root.TryGetProperty("provider", out var pVal) && pVal.ValueKind == JsonValueKind.String)
                {
                    providerKey ??= pVal.GetString();
                }
                if (root.TryGetProperty("maskedValue", out var mVal) && mVal.ValueKind == JsonValueKind.String)
                {
                    resourceRef ??= mVal.GetString();
                }
                if (root.TryGetProperty("evidenceReference", out var eRef) && eRef.ValueKind == JsonValueKind.String)
                {
                    resourceRef ??= eRef.GetString();
                }
            }
            catch (JsonException)
            {
                // Ignore invalid JSON payloads safely
            }
        }

        return (providerKey, resourceRef);
    }

    private static RemediationRecommendationDecision EvaluatePolicyMatrix(
        SecurityFinding finding,
        string? providerKey,
        string? resourceRef,
        RemediationRecommendationPolicyOptions options)
    {
        var decision = new RemediationRecommendationDecision
        {
            ShouldRecommend = true,
            RequiresApproval = true
        };

        switch (finding.FindingType)
        {
            case FindingType.ValidatedCredentialExposed:
                if (options.EnableRevocationRecommendations)
                {
                    decision.ActionType = RemediationActionType.RevokeCredential;
                    decision.Confidence = RecommendationConfidence.High;
                    decision.ReasonCodes.Add("VALIDATED_SECRET_EXPOSED");
                    decision.Title = "Revoke Exposed Validated Credential";
                    decision.Description = "Immediately revoke exposed active credential at provider to prevent unauthorized system access.";
                    decision.Reason = "Active valid credential detected in repository source code.";
                }
                else
                {
                    decision.ActionType = RemediationActionType.InvestigateExposure;
                    decision.Confidence = RecommendationConfidence.Medium;
                    decision.ReasonCodes.Add("REVOCATION_POLICY_DISABLED");
                    decision.Title = "Investigate Validated Credential Exposure";
                    decision.Description = "Perform security investigation for validated credential exposure (Revocation policy disabled).";
                    decision.Reason = "Credential revocation recommendations disabled in policy configuration.";
                }
                break;

            case FindingType.OverprivilegedCredential:
                decision.ActionType = RemediationActionType.RestrictCredentialScope;
                decision.Confidence = RecommendationConfidence.High;
                decision.ReasonCodes.Add("OVERPRIVILEGED_SCOPE");
                decision.Title = "Restrict Overprivileged Credential Scope";
                decision.Description = "Modify credential permissions at provider to enforce principle of least privilege.";
                decision.Reason = "Exposed credential carries excess administrative or multi-environment permissions.";
                break;

            case FindingType.ProductionServiceExposed:
                decision.ActionType = RemediationActionType.DisableExposedService;
                decision.Confidence = RecommendationConfidence.High;
                decision.ReasonCodes.Add("PRODUCTION_SERVICE_EXPOSED");
                decision.Title = "Isolate Exposed Production Service";
                decision.Description = "Disable or restrict public network access for exposed production endpoint/integration.";
                decision.Reason = "Production service endpoint or integration secret detected in public configuration.";
                break;

            case FindingType.HistoricalExposureDetected:
                if (options.EnableHistoricalExposureRecommendations)
                {
                    decision.ActionType = RemediationActionType.RemoveHistoricalExposure;
                    decision.Confidence = RecommendationConfidence.Medium;
                    decision.ReasonCodes.Add("HISTORICAL_COMMIT_EXPOSURE");
                    decision.Title = "Scrub Historical Commit Secret Exposure";
                    decision.Description = "Purge exposed secret candidate from repository git commit history (Recommendation only).";
                    decision.Reason = "Secret candidate detected in historical git commits.";
                }
                else
                {
                    decision.ActionType = RemediationActionType.InvestigateExposure;
                    decision.Confidence = RecommendationConfidence.Low;
                    decision.ReasonCodes.Add("HISTORICAL_POLICY_DISABLED");
                    decision.Title = "Investigate Historical Exposure";
                    decision.Description = "Review historical commit exposure evidence.";
                    decision.Reason = "Historical exposure recommendations disabled in configuration.";
                }
                break;

            case FindingType.DatabaseExposure:
                if (options.EnableRotationRecommendations)
                {
                    decision.ActionType = RemediationActionType.RotateCredential;
                    decision.Confidence = RecommendationConfidence.High;
                    decision.ReasonCodes.Add("DATABASE_CREDENTIAL_EXPOSED");
                    decision.Title = "Rotate Database Connection Credential";
                    decision.Description = "Rotate database password and update application secret manager stores.";
                    decision.Reason = "Database connection string or password detected in source repository.";
                }
                else
                {
                    decision.ActionType = RemediationActionType.InvestigateExposure;
                    decision.Confidence = RecommendationConfidence.Medium;
                    decision.ReasonCodes.Add("ROTATION_POLICY_DISABLED");
                    decision.Title = "Investigate Database Exposure";
                    decision.Description = "Triage database credential exposure.";
                    decision.Reason = "Credential rotation policy disabled in configuration.";
                }
                break;

            case FindingType.ExpiredCredentialExposed:
                decision.ActionType = RemediationActionType.InvestigateExposure;
                decision.Confidence = RecommendationConfidence.Medium;
                decision.ReasonCodes.Add("CREDENTIAL_EXPIRED");
                decision.Title = "Investigate Expired Credential Exposure";
                decision.Description = "Audit exposure source and verify that credential cannot be renewed or reused.";
                decision.Reason = "Exposed credential confirmed expired by provider check.";
                break;

            case FindingType.UnvalidatedCredentialExposed:
            default:
                if (string.IsNullOrWhiteSpace(providerKey))
                {
                    decision.ActionType = RemediationActionType.InvestigateExposure;
                    decision.Confidence = RecommendationConfidence.Low;
                    decision.ReasonCodes.Add("PROVIDER_CONTEXT_INSUFFICIENT");
                    decision.Title = "Investigate Ambiguous Secret Exposure";
                    decision.Description = "Perform security triage to establish provider type and secret validity before taking action.";
                    decision.Reason = "Insufficient provider metadata available for automated action recommendation.";
                }
                else
                {
                    decision.ActionType = RemediationActionType.InvestigateExposure;
                    decision.Confidence = RecommendationConfidence.Medium;
                    decision.ReasonCodes.Add("UNVALIDATED_SECRET_DETECTED");
                    decision.Title = "Investigate Unvalidated Secret Exposure";
                    decision.Description = "Validate candidate secret against provider and assess exposure impact.";
                    decision.Reason = "Unvalidated secret candidate detected in source code.";
                }
                break;
        }

        return decision;
    }

    private static RemediationRecommendationDecision CreateNegativeDecision(string reasonCode, string reason)
    {
        return new RemediationRecommendationDecision
        {
            ShouldRecommend = false,
            ActionType = RemediationActionType.InvestigateExposure,
            Confidence = RecommendationConfidence.Low,
            Reason = reason,
            ReasonCodes = new List<string> { reasonCode },
            RequiresApproval = true,
            ExplanationJson = JsonSerializer.Serialize(new { reasonCode, reason })
        };
    }
}
