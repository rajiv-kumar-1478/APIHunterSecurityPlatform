using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class AnalysisJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public JobType JobType { get; set; }
    public JobStatus Status { get; set; } = JobStatus.Queued;
    public int Priority { get; set; }
    public string TargetEntityType { get; set; } = string.Empty; // "Repository", "Snapshot"
    public Guid TargetEntityId { get; set; }
    public string? PayloadJson { get; set; }
    public string? ResultJson { get; set; }
    public string? ErrorMessage { get; set; }
    public int RetryCount { get; set; }
    public int MaxRetries { get; set; } = 3;

    /// <summary>
    /// Stable work unit checkpoint: SnapshotFileId last processed.
    /// </summary>
    public Guid? CheckpointFileId { get; set; }

    public string? WorkerInstanceId { get; set; }
    public DateTime QueuedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public DateTime? LastHeartbeatAtUtc { get; set; }
    public DateTime? NextRetryAtUtc { get; set; }
    public Guid? QueuedByUserId { get; set; }
    public string CorrelationId { get; set; } = string.Empty;

    /// <summary>
    /// EF Core Optimistic Concurrency token.
    /// </summary>
    public byte[] RowVersion { get; set; } = [];

    // Navigation
    public User? QueuedByUser { get; set; }
}
