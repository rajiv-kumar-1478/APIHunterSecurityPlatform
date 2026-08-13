using Platform.Domain.Enums;

namespace Platform.Domain.Contracts;

public enum RecommendationConfidence
{
    Low,
    Medium,
    High
}

public class RemediationRecommendationDecision
{
    public bool ShouldRecommend { get; set; }
    public RemediationActionType ActionType { get; set; }
    public RecommendationConfidence Confidence { get; set; } = RecommendationConfidence.Medium;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public List<string> ReasonCodes { get; set; } = new();

    /// <summary>
    /// Safety flag requiring explicit human approval before execution. Always true by default.
    /// </summary>
    public bool RequiresApproval { get; set; } = true;

    public string? ProviderKey { get; set; }
    public string? ProviderResourceReference { get; set; }

    public string ExplanationJson { get; set; } = "{}";
}
