namespace Platform.Application.Configuration;

public class RemediationRecommendationPolicyOptions
{
    public const string SectionName = "RemediationRecommendationPolicy";

    public bool EngineEnabled { get; set; } = true;
    public int MinimumRiskScoreForRecommendation { get; set; } = 30;
    public bool EnableRevocationRecommendations { get; set; } = true;
    public bool EnableRotationRecommendations { get; set; } = true;
    public bool EnableHistoricalExposureRecommendations { get; set; } = true;
    public int DefaultApprovalLeaseHours { get; set; } = 24;
}
