using System.Text.Json;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Pure, in-memory policy evaluation engine for assessing organizational response rules and allowlists.
/// STRICT BOUNDARY: Pure in-memory logic. Zero DB calls, zero provider API calls, zero audit logging, zero secret decryption.
/// </summary>
public class ResponsePolicyEngine
{
    private static readonly HashSet<FindingStatus> InactiveFindingStatuses = new()
    {
        FindingStatus.Resolved,
        FindingStatus.Remediated,
        FindingStatus.FalsePositive,
        FindingStatus.AcceptedRisk
    };

    public ResponsePolicyEvaluationResult Evaluate(
        RemediationRecommendationDecision decision,
        SecurityFinding finding,
        ResponsePolicyOptions? options = null,
        string? repositoryEnvironment = null)
    {
        options ??= new ResponsePolicyOptions();

        // 1. Engine Enabled Check (Fail-Closed)
        if (!options.Enabled)
        {
            return CreateDenyResult(options.PolicyVersion, "POLICY_ENGINE_DISABLED", "RULE_ENGINE_DISABLED", "Response policy engine is disabled in configuration (Fail-Closed).");
        }

        if (decision == null || finding == null)
        {
            return CreateDenyResult(options.PolicyVersion, "NULL_INPUT_CONTEXT", "RULE_NULL_CONTEXT", "Finding or recommendation decision context is null (Fail-Closed).");
        }

        // 2. Finding Active Check
        if (InactiveFindingStatuses.Contains(finding.Status))
        {
            return CreateDenyResult(options.PolicyVersion, "INACTIVE_FINDING_PROPOSAL_DENIED", "RULE_INACTIVE_FINDING", $"Finding status '{finding.Status}' is inactive. Proposal denied.");
        }

        // 3. Recommendation Decision Check
        if (!decision.ShouldRecommend)
        {
            return CreateDenyResult(options.PolicyVersion, "DECISION_NOT_RECOMMENDED", "RULE_NOT_RECOMMENDED", "Recommendation decision does not recommend proposal.");
        }

        // 4. Minimum Risk Score Bound Check
        if (finding.RiskScore < options.MinimumRiskScoreToPropose)
        {
            return CreateDenyResult(
                options.PolicyVersion,
                "RISK_SCORE_BELOW_POLICY_MINIMUM",
                "RULE_MIN_RISK_SCORE",
                $"Finding risk score {finding.RiskScore} is below policy minimum required {options.MinimumRiskScoreToPropose}.");
        }

        // 5. Minimum Severity Bound Check
        if (finding.Severity < options.MinimumSeverityToPropose)
        {
            return CreateDenyResult(
                options.PolicyVersion,
                "SEVERITY_BELOW_POLICY_MINIMUM",
                "RULE_MIN_SEVERITY",
                $"Finding severity '{finding.Severity}' is below policy minimum required '{options.MinimumSeverityToPropose}'.");
        }

        // 6. Action Type Allowlist Check
        if (!options.AllowedActionTypes.Contains(decision.ActionType))
        {
            return CreateDenyResult(
                options.PolicyVersion,
                "ACTION_TYPE_DISALLOWED_BY_POLICY",
                "RULE_ACTION_TYPE_DISALLOWED",
                $"Remediation action type '{decision.ActionType}' is not in policy allowed action types.");
        }

        // 7. Provider Allowlist Check
        if (!string.IsNullOrWhiteSpace(decision.ProviderKey) && !options.AllowedProviders.Contains(decision.ProviderKey))
        {
            return CreateDenyResult(
                options.PolicyVersion,
                "PROVIDER_DISALLOWED_BY_POLICY",
                "RULE_PROVIDER_DISALLOWED",
                $"Provider '{decision.ProviderKey}' is not in policy allowed provider list.");
        }

        // 8. Production Environment Restrictions Check
        string env = string.IsNullOrWhiteSpace(repositoryEnvironment) ? "Unknown" : repositoryEnvironment.Trim();
        bool isProdDisallowedAction = options.DisallowedActionTypesInProduction.Contains(decision.ActionType);

        if (isProdDisallowedAction)
        {
            if (string.Equals(env, "Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return CreateDenyResult(
                    options.PolicyVersion,
                    "UNKNOWN_ENVIRONMENT_FAIL_CLOSED",
                    "RULE_UNKNOWN_ENV_FAIL_CLOSED",
                    $"Environment is 'Unknown' for action '{decision.ActionType}' which requires strict environment classification (Fail-Closed).");
            }
            if (string.Equals(env, "Production", StringComparison.OrdinalIgnoreCase))
            {
                return CreateDenyResult(
                    options.PolicyVersion,
                    "PRODUCTION_ACTION_DISALLOWED",
                    "RULE_PROD_ACTION_DISALLOWED",
                    $"Action '{decision.ActionType}' is explicitly disallowed in Production environment policy.");
            }
        }

        // 9. Policy Allow Result
        var auditMetadata = JsonSerializer.Serialize(new
        {
            actionType = decision.ActionType.ToString(),
            providerKey = decision.ProviderKey,
            policyVersion = options.PolicyVersion,
            environment = env
        });

        return new ResponsePolicyEvaluationResult(
            IsAllowed: true,
            PolicyVersion: options.PolicyVersion,
            DenialReason: null,
            ReasonCodes: new[] { "POLICY_ALLOWED" },
            MatchedRuleId: "RULE_POLICY_ALLOWED",
            EvaluatedAtUtc: DateTime.UtcNow,
            AuditMetadataJson: auditMetadata);
    }

    private static ResponsePolicyEvaluationResult CreateDenyResult(string policyVersion, string reasonCode, string ruleId, string denialReason)
    {
        var auditMetadata = JsonSerializer.Serialize(new
        {
            policyVersion,
            reasonCode,
            ruleId,
            denialReason
        });

        return new ResponsePolicyEvaluationResult(
            IsAllowed: false,
            PolicyVersion: policyVersion,
            DenialReason: denialReason,
            ReasonCodes: new[] { reasonCode },
            MatchedRuleId: ruleId,
            EvaluatedAtUtc: DateTime.UtcNow,
            AuditMetadataJson: auditMetadata);
    }
}
