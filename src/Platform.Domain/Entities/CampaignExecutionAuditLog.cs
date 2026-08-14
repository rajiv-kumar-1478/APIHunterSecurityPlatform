using System;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable audit log capturing every campaign trigger evaluation, scheduler decision, and execution dispatch.
/// </summary>
public class CampaignExecutionAuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Foreign key to parent campaign.
    /// </summary>
    public Guid CampaignId { get; set; }
    public ScanCampaign? Campaign { get; set; }

    /// <summary>
    /// Tenant ownership boundary.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Authoritative decision reached: Dispatched, SkippedAlreadyRunning, QueuedNext, RejectedConcurrent, etc.
    /// </summary>
    public SchedulerDecision Decision { get; set; }

    /// <summary>
    /// Source triggering the evaluation: 'Scheduler', 'ManualRunNow', etc.
    /// </summary>
    public string TriggerSource { get; set; } = "Scheduler";

    /// <summary>
    /// Schedule version at the moment of evaluation.
    /// </summary>
    public long ScheduleVersion { get; set; }

    /// <summary>
    /// Exact UTC timestamp when the trigger was evaluated.
    /// </summary>
    public DateTime EvaluatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Foreign key to the created SecurityScanJob if decision was Dispatched or QueuedNext; null if skipped/rejected.
    /// </summary>
    public Guid? DispatchedScanJobId { get; set; }

    /// <summary>
    /// Detailed diagnostic message explaining the decision rationale.
    /// </summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// Optional serialized JSON metadata for diagnostics and observability.
    /// </summary>
    public string? MetadataJson { get; set; }
}
