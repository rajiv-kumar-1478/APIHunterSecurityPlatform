using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RemediationExecution
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RemediationActionId { get; set; }
    public int ActionVersion { get; set; }

    public RemediationExecutionStatus Status { get; set; } = RemediationExecutionStatus.Executing;

    public string ProviderKey { get; set; } = string.Empty;
    public string? ProviderResourceReference { get; set; }

    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }
    public long? ExecutionDurationMs { get; set; }

    public bool Success { get; set; }
    public string? FailureCode { get; set; }
    public string? FailureReason { get; set; }
    public string? ProviderOperationId { get; set; }

    public int? PreExecutionRiskScore { get; set; }
    public int? PostExecutionRiskScore { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public RemediationAction RemediationAction { get; set; } = null!;
}
