using Platform.Domain.Enums;

namespace Platform.Application.Configuration;

public class ResponsePolicyOptions
{
    public const string SectionName = "ResponsePolicy";

    public bool Enabled { get; set; } = true;
    public bool FailClosed { get; set; } = true;
    public string PolicyVersion { get; set; } = "v1.0";

    public RiskSeverity MinimumSeverityToPropose { get; set; } = RiskSeverity.Low;
    public int MinimumRiskScoreToPropose { get; set; } = 30;

    public HashSet<RemediationActionType> AllowedActionTypes { get; set; } = new()
    {
        RemediationActionType.RevokeCredential,
        RemediationActionType.RotateCredential,
        RemediationActionType.RestrictCredentialScope,
        RemediationActionType.RemoveCurrentExposure,
        RemediationActionType.RemoveHistoricalExposure,
        RemediationActionType.DisableExposedService,
        RemediationActionType.InvestigateExposure
    };

    public HashSet<string> AllowedProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "openai",
        "anthropic",
        "github",
        "aws",
        "slack",
        "stripe",
        "sendgrid",
        "mailgun",
        "groq",
        "deepseek"
    };

    public HashSet<RemediationActionType> DisallowedActionTypesInProduction { get; set; } = new()
    {
        RemediationActionType.RemoveHistoricalExposure
    };

    public int MaxProposedActionsPerFinding { get; set; } = 5;
}
