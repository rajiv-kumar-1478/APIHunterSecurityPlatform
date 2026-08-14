using System;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Pure deterministic calculator for continuous scan campaign schedules (Cron and Fixed Interval).
/// Evaluates standard IANA timezones and daylight saving time transitions.
/// </summary>
public interface ICampaignScheduleCalculator
{
    /// <summary>
    /// Evaluates the next scheduled occurrence in UTC relative to a reference timestamp.
    /// </summary>
    CampaignScheduleCalculationResult CalculateNextOccurrence(
        ScheduleType scheduleType,
        string? cronExpression,
        TimeSpan? intervalDuration,
        string timeZoneId,
        DateTime referenceTimeUtc);

    /// <summary>
    /// Validates the schedule parameters and throws ArgumentException if invalid.
    /// </summary>
    void ValidateSchedule(
        ScheduleType scheduleType,
        string? cronExpression,
        TimeSpan? intervalDuration,
        string timeZoneId);
}
