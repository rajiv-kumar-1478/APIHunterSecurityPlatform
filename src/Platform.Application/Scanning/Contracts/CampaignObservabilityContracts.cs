using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Operational health status enum with strict evaluation precedence:
/// FailClosed > Unavailable > Degraded > NotConfigured > Healthy
/// </summary>
public enum CampaignOperationalHealthStatus
{
    Healthy = 1,
    Degraded = 2,
    Unavailable = 3,
    NotConfigured = 4,
    FailClosed = 5
}

/// <summary>
/// Tenant-isolated operational health DTO for scan campaigns.
/// </summary>
public sealed record CampaignOperationalHealthDto(
    Guid TenantId,
    CampaignOperationalHealthStatus Status,
    string StatusReason,
    int TotalCampaigns,
    int ActiveCampaigns,
    int PausedCampaigns,
    int AutoPausedCampaigns,
    int OverdueCampaignsCount,
    DateTime? LastSchedulerTickUtc,
    bool SchedulerWorkerAlive,
    CampaignWindowMetricsDto Metrics24h,
    CampaignWindowMetricsDto Metrics7d,
    DateTime EvaluatedAtUtc
);

/// <summary>
/// Time-bounded execution telemetry window metrics.
/// </summary>
public sealed record CampaignWindowMetricsDto(
    TimeSpan Window,
    int TotalEvaluations,
    int DispatchedCount,
    int SkippedCount,
    int CompletedScansCount,
    int FailedScansCount,
    int RecoveredStuckCount,
    double SuccessRatePercentage,
    double AverageScanDurationSeconds
);

/// <summary>
/// Immutable correlated execution history entry combining audit decision with linked scan job outcome.
/// </summary>
public sealed record CampaignExecutionHistoryEntryDto(
    Guid AuditLogId,
    Guid CampaignId,
    string CampaignName,
    Guid TenantId,
    SchedulerDecision Decision,
    string TriggerSource,
    long ScheduleVersion,
    DateTime EvaluatedAtUtc,
    string Reason,
    string? OccurrenceKey,
    // Correlated Scan Job Data (joined from security_scan_jobs)
    Guid? ScanJobId,
    SecurityScanJobStatus? ScanJobStatus,
    string? TargetUrl,
    SecurityScanProfileType? ScanProfile,
    DateTime? ScanStartedAtUtc,
    DateTime? ScanCompletedAtUtc,
    double? ScanDurationSeconds,
    int? TotalFindingsCount,
    string? ScanFailureReason
);

/// <summary>
/// Introspection diagnostics for a scan campaign, including failure streak analysis and recovery events.
/// </summary>
public sealed record CampaignDiagnosticsDto(
    Guid CampaignId,
    string CampaignName,
    CampaignStatus Status,
    int ConsecutiveFailuresCount,
    int MaxConsecutiveFailures,
    bool AutoPauseOnConsecutiveFailures,
    string? AutoPauseReason,
    DateTime? AutoPausedAtUtc,
    long ScheduleVersion,
    DateTime? NextRunUtc,
    DateTime? LastRunUtc,
    bool IsOverdue,
    TimeSpan? OverdueBy,
    IReadOnlyList<CampaignFailureStreakEventDto> RecentFailureStreak,
    IReadOnlyList<CampaignRecoveryEventDto> RecentRecoveries
);

/// <summary>
/// Individual failure event in a campaign's diagnostic failure streak.
/// </summary>
public sealed record CampaignFailureStreakEventDto(
    Guid? ScanJobId,
    DateTime TimestampUtc,
    string FailureType, // "ScanFailed", "StuckTimeout", "TargetDisabled", "ClaimLost"
    string Reason
);

/// <summary>
/// Individual stuck-job recovery event sourced from immutable audit log records.
/// </summary>
public sealed record CampaignRecoveryEventDto(
    Guid AuditLogId,
    Guid? ScanJobId,
    DateTime RecoveredAtUtc,
    string TriggerSource,
    string Reason,
    string? MetadataJson
);
