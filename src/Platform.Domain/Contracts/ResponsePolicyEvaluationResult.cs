namespace Platform.Domain.Contracts;

public sealed record ResponsePolicyEvaluationResult(
    bool IsAllowed,
    string PolicyVersion,
    string? DenialReason,
    IReadOnlyList<string> ReasonCodes,
    string? MatchedRuleId,
    DateTime EvaluatedAtUtc,
    string AuditMetadataJson);
