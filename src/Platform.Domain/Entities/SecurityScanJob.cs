using System;
using System.ComponentModel.DataAnnotations;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityScanJob
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? RepositoryId { get; set; }

    public Guid? TargetId { get; set; }

    public string TargetUrl { get; set; } = string.Empty;

    public SecurityScanProfileType ScanProfile { get; set; } = SecurityScanProfileType.Recon;

    public SecurityScanJobStatus Status { get; set; } = SecurityScanJobStatus.Queued;

    /// <summary>
    /// Required tenant boundary owning this job. It is independent from the requesting actor.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// User who requested the job, or null for scheduler-created system jobs.
    /// </summary>
    public Guid? RequestedByUserId { get; set; }

    public string ProviderKey { get; set; } = string.Empty;

    public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime? StartedAtUtc { get; set; }

    public DateTime? CompletedAtUtc { get; set; }

    public DateTime? CancelledAtUtc { get; set; }

    public string? FailureReason { get; set; }

    public string? ExecutionReceiptJson { get; set; }

    public int ProgressPercentage { get; set; } = 0;

    public string? CurrentPhase { get; set; }

    public string? CurrentTool { get; set; }

    public int TotalFindingsCount { get; set; } = 0;

    public Guid? RetryOfJobId { get; set; }

    /// <summary>
    /// Foreign key to parent continuous scan campaign if job was dispatched by a campaign.
    /// </summary>
    public Guid? CampaignId { get; set; }

    /// <summary>
    /// Source triggering the execution: 'Manual', 'CampaignScheduler', 'CampaignRunNow', 'CiCdWebhook', etc.
    /// </summary>
    public string TriggeredBy { get; set; } = "Manual";

    /// <summary>
    /// EF Core Optimistic Concurrency Token for job-level mutations (e.g. recovery race).
    /// Recovery UPDATE includes WHERE JobVersion = @expected; live worker heartbeat increments this,
    /// causing a DbUpdateConcurrencyException in the recovery path → recovery loses the race safely.
    /// </summary>
    [ConcurrencyCheck]
    public int JobVersion { get; set; } = 1;

    /// <summary>
    /// Identifies which worker instance picked up and started this job.
    /// Set at job start; used for observability and stuck-job attribution.
    /// </summary>
    public string? WorkerInstanceId { get; set; }

    /// <summary>
    /// Last UTC timestamp at which the executing worker confirmed liveness.
    /// Updated periodically (not just at start) by GenericScanWorker.
    /// Recovery considers a job stuck when: Status=Running AND LastHeartbeatUtc &lt; (now - threshold).
    /// </summary>
    public DateTime? LastHeartbeatUtc { get; set; }

    /// <summary>
    /// Deterministic idempotency key for scheduled occurrences.
    /// SHA-256( CampaignId + ScheduledOccurrenceUtc."O" + ScheduleVersion ).
    /// Null for manual/run-now jobs. A unique index on (CampaignId, CampaignOccurrenceKey)
    /// prevents duplicate dispatch on scheduler retry after an ambiguous failure.
    /// </summary>
    public string? CampaignOccurrenceKey { get; set; }

    /// <summary>
    /// Marks that this job's terminal result has been applied to its parent campaign.
    /// The marker is persisted in the same transaction as campaign counters so outcome
    /// delivery can be retried safely after worker or database failures.
    /// </summary>
    public DateTime? CampaignOutcomeProcessedAtUtc { get; set; }

    // Navigation properties
    public Repository? Repository { get; set; }
    public SecurityTarget? Target { get; set; }
    public User? RequestedByUser { get; set; }
    public ScanCampaign? Campaign { get; set; }
}
