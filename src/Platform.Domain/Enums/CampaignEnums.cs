namespace Platform.Domain.Enums;

/// <summary>
/// Operational status of a scheduled continuous scan campaign.
/// </summary>
public enum CampaignStatus
{
    Active = 1,
    Paused = 2,
    Archived = 3,
    AutoPaused = 4
}

/// <summary>
/// Type of schedule cadence governing the campaign.
/// </summary>
public enum ScheduleType
{
    Cron = 1,
    Interval = 2
}

/// <summary>
/// Concurrency handling behavior when a new trigger arrives while a previous scan job is still running.
/// </summary>
public enum CampaignConcurrencyPolicy
{
    /// <summary>
    /// Skip the current trigger without creating a new job (Default).
    /// </summary>
    SkipIfRunning = 1,

    /// <summary>
    /// Enqueue at most ONE pending job to execute once the running job completes (Queue depth capped at 1).
    /// </summary>
    QueueNext = 2,

    /// <summary>
    /// Reject the trigger and record a concurrency violation skip.
    /// </summary>
    ForbidConcurrent = 3
}

/// <summary>
/// Authoritative scheduler decision recorded for every trigger evaluation.
/// </summary>
public enum SchedulerDecision
{
    Dispatched = 1,
    SkippedAlreadyRunning = 2,
    QueuedNext = 3,
    RejectedConcurrent = 4,
    SkippedQueueFull = 5,
    SkippedTargetDisabled = 6,
    SkippedProfileInvalid = 7,
    SkippedScopeUnapproved = 8
}
