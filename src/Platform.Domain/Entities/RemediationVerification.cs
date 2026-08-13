using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RemediationVerification
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RemediationActionId { get; set; }
    public Guid? RemediationExecutionId { get; set; }

    public RemediationVerificationStatus Status { get; set; } = RemediationVerificationStatus.Pending;

    public DateTime VerifiedAtUtc { get; set; } = DateTime.UtcNow;

    public int PreExecutionRiskScore { get; set; }
    public int PostExecutionRiskScore { get; set; }
    public int RiskDelta { get; set; }

    public string? ValidationResultStatus { get; set; }
    public string VerificationDetailsJson { get; set; } = "{}";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public RemediationAction RemediationAction { get; set; } = null!;
    public RemediationExecution? RemediationExecution { get; set; }
}
