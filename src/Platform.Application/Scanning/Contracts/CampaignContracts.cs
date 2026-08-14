using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

public sealed record CreateCampaignRequest(
    string Name,
    string? Description,
    Guid RepositoryId,
    Guid SecurityTargetId,
    SecurityScanProfileType ScanProfile = SecurityScanProfileType.Standard,
    ScheduleType ScheduleType = ScheduleType.Interval,
    string? CronExpression = null,
    int? IntervalMinutes = null,
    string TimeZoneId = "UTC",
    CampaignConcurrencyPolicy ConcurrencyPolicy = CampaignConcurrencyPolicy.SkipIfRunning,
    int MaxConsecutiveFailures = 5,
    bool AutoPauseOnConsecutiveFailures = true
);

public sealed record UpdateCampaignRequest(
    string? Name = null,
    string? Description = null,
    SecurityScanProfileType? ScanProfile = null,
    ScheduleType? ScheduleType = null,
    string? CronExpression = null,
    int? IntervalMinutes = null,
    string? TimeZoneId = null,
    CampaignConcurrencyPolicy? ConcurrencyPolicy = null,
    int? MaxConsecutiveFailures = null,
    bool? AutoPauseOnConsecutiveFailures = null
);

public sealed record ScanCampaignDto(
    Guid Id,
    Guid TenantId,
    Guid RepositoryId,
    string? RepositoryName,
    Guid SecurityTargetId,
    string? SecurityTargetName,
    string? TargetUrl,
    string Name,
    string? Description,
    CampaignStatus Status,
    SecurityScanProfileType ScanProfile,
    ScheduleType ScheduleType,
    string? CronExpression,
    TimeSpan? IntervalDuration,
    string TimeZoneId,
    CampaignConcurrencyPolicy ConcurrencyPolicy,
    long ScheduleVersion,
    DateTime? NextRunUtc,
    DateTime? LastRunUtc,
    Guid? LastScanJobId,
    int TotalRunsCount,
    int ConsecutiveFailuresCount,
    int MaxConsecutiveFailures,
    bool AutoPauseOnConsecutiveFailures,
    DateTime CreatedAtUtc,
    DateTime? UpdatedAtUtc
);

public sealed record CampaignExecutionAuditLogDto(
    Guid Id,
    Guid CampaignId,
    Guid TenantId,
    SchedulerDecision Decision,
    string TriggerSource,
    long ScheduleVersion,
    DateTime EvaluatedAtUtc,
    Guid? DispatchedScanJobId,
    string Reason,
    string? MetadataJson
);

public sealed record CampaignScheduleCalculationResult(
    bool IsValid,
    DateTime? NextOccurrenceUtc,
    string? ErrorMessage,
    string NormalizedTimeZoneId,
    string? Description
);

public sealed record CampaignRunNowResult(
    Guid CampaignId,
    SchedulerDecision Decision,
    Guid? DispatchedScanJobId,
    string Reason,
    DateTime EvaluatedAtUtc
);

/// <summary>
/// Summary of outcomes from a single scheduler polling tick across all due campaigns.
/// </summary>
public sealed record CampaignSchedulerTickResult(
    int CampaignsEvaluated,
    int Dispatched,
    int Skipped,
    int ClaimLost,
    int Errors,
    DateTime TickStartUtc,
    DateTime TickEndUtc
);
