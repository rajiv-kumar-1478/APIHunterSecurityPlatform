using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class AiInvestigationJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public Guid SnapshotId { get; set; }
    public AiInvestigationStageType CurrentStage { get; set; } = AiInvestigationStageType.RepositoryMetadata;
    public int CompletedStagesCount { get; set; } = 0;
    public string ActiveProviderName { get; set; } = string.Empty;
    public string ActiveModelName { get; set; } = string.Empty;
    public int TotalPromptTokens { get; set; } = 0;
    public int TotalCompletionTokens { get; set; } = 0;
    public JobStatus Status { get; set; } = JobStatus.Queued;
    public string? ErrorMessage { get; set; }
    public string? WorkerId { get; set; }
    public Guid ClaimToken { get; set; } = Guid.Empty;
    public DateTime? LastHeartbeatAtUtc { get; set; }
    public DateTime QueuedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }

    // Navigation
    public Repository Repository { get; set; } = null!;
    public RepositorySnapshot Snapshot { get; set; } = null!;
    public ICollection<AiInvestigationCheckpoint> Checkpoints { get; set; } = new List<AiInvestigationCheckpoint>();
    public ICollection<AiInvestigationEvidence> Evidences { get; set; } = new List<AiInvestigationEvidence>();
}
