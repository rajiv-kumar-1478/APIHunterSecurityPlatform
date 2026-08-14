using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Authoritative policy and continuous scheduling entity for recurring security scans.
/// Each campaign owns one target, one scan profile, and one schedule definition.
/// Does not duplicate scanner execution logic; dispatches standard SecurityScanJob primitives.
/// </summary>
public class ScanCampaign
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Tenant boundary owning the campaign.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Repository boundary associated with the campaign and target.
    /// </summary>
    public Guid RepositoryId { get; set; }
    public Repository? Repository { get; set; }

    /// <summary>
    /// Governed security target evaluated during each campaign execution.
    /// </summary>
    public Guid SecurityTargetId { get; set; }
    public SecurityTarget? SecurityTarget { get; set; }

    /// <summary>
    /// Human-readable display name of the campaign.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Optional description or operational notes.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Lifecycle status: Active, Paused, Archived, AutoPaused.
    /// </summary>
    public CampaignStatus Status { get; set; } = CampaignStatus.Active;

    /// <summary>
    /// Standard security scan profile (Recon, Standard, Deep).
    /// </summary>
    public SecurityScanProfileType ScanProfile { get; set; } = SecurityScanProfileType.Standard;

    /// <summary>
    /// Schedule model: Cron or Fixed Interval.
    /// </summary>
    public ScheduleType ScheduleType { get; set; } = ScheduleType.Interval;

    /// <summary>
    /// Standard 5-part cron expression (e.g., '0 2 * * *' for daily 2 AM).
    /// Required when ScheduleType is Cron; null otherwise.
    /// </summary>
    public string? CronExpression { get; set; }

    /// <summary>
    /// Fixed duration between scan runs (e.g., 24h, 7d). Must be >= 15 minutes.
    /// Required when ScheduleType is Interval; null otherwise.
    /// </summary>
    public TimeSpan? IntervalDuration { get; set; }

    /// <summary>
    /// Canonical IANA/TZDB timezone identifier (e.g., 'UTC', 'Asia/Kolkata', 'America/New_York').
    /// </summary>
    public string TimeZoneId { get; set; } = "UTC";

    /// <summary>
    /// Concurrency policy when previous scan is still running at trigger time.
    /// </summary>
    public CampaignConcurrencyPolicy ConcurrencyPolicy { get; set; } = CampaignConcurrencyPolicy.SkipIfRunning;

    /// <summary>
    /// Monotonically increasing version token for optimistic concurrency and stale scheduler dispatch rejection.
    /// </summary>
    public long ScheduleVersion { get; set; } = 1;

    /// <summary>
    /// Authoritative database scheduler cursor. Represents the next eligible scheduled timestamp in UTC.
    /// </summary>
    public DateTime? NextRunUtc { get; set; }

    /// <summary>
    /// Timestamp of the most recent execution attempt.
    /// </summary>
    public DateTime? LastRunUtc { get; set; }

    /// <summary>
    /// Foreign key of the most recently dispatched scan job.
    /// </summary>
    public Guid? LastScanJobId { get; set; }

    /// <summary>
    /// Total number of scan triggers evaluated.
    /// </summary>
    public int TotalRunsCount { get; set; }

    /// <summary>
    /// Number of consecutive execution failures (used for auto-pause threshold).
    /// </summary>
    public int ConsecutiveFailuresCount { get; set; }

    /// <summary>
    /// Maximum consecutive execution failures before triggering AutoPause (default: 5).
    /// </summary>
    public int MaxConsecutiveFailures { get; set; } = 5;

    /// <summary>
    /// Whether to auto-pause the campaign when consecutive failures reach threshold.
    /// </summary>
    public bool AutoPauseOnConsecutiveFailures { get; set; } = true;

    /// <summary>
    /// Record creation timestamp in UTC.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Record last update timestamp in UTC.
    /// </summary>
    public DateTime? UpdatedAtUtc { get; set; }

    /// <summary>
    /// Audit log history of scheduler decisions and manual triggers.
    /// </summary>
    public ICollection<CampaignExecutionAuditLog> AuditLogs { get; set; } = new List<CampaignExecutionAuditLog>();

    /// <summary>
    /// Dispatched scan jobs associated with this campaign.
    /// </summary>
    public ICollection<SecurityScanJob> ScanJobs { get; set; } = new List<SecurityScanJob>();
}
