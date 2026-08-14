using System;
using Cronos;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Deterministic campaign schedule calculator implementing Cron and Fixed-Interval scheduling.
/// Enforces:
/// 1. Minimum interval ceiling of 15 minutes to prevent scan storms.
/// 2. Canonical IANA timezone resolution (e.g., 'Asia/Kolkata', 'America/New_York', 'UTC').
/// 3. Strict 5-part standard Cron syntax validation.
/// 4. Explicit DST transition disambiguation.
/// </summary>
public class CampaignScheduleCalculator : ICampaignScheduleCalculator
{
    public static readonly TimeSpan MinimumInterval = TimeSpan.FromMinutes(15);
    private readonly ILogger<CampaignScheduleCalculator> _logger;

    public CampaignScheduleCalculator(ILogger<CampaignScheduleCalculator>? logger = null)
    {
        _logger = logger ?? NullLogger<CampaignScheduleCalculator>.Instance;
    }

    public CampaignScheduleCalculationResult CalculateNextOccurrence(
        ScheduleType scheduleType,
        string? cronExpression,
        TimeSpan? intervalDuration,
        string timeZoneId,
        DateTime referenceTimeUtc)
    {
        try
        {
            ValidateSchedule(scheduleType, cronExpression, intervalDuration, timeZoneId);

            var tz = ResolveTimeZone(timeZoneId);
            var refUtc = DateTime.SpecifyKind(referenceTimeUtc, DateTimeKind.Utc);

            if (scheduleType == ScheduleType.Interval)
            {
                var nextUtc = refUtc.Add(intervalDuration!.Value);
                return new CampaignScheduleCalculationResult(
                    IsValid: true,
                    NextOccurrenceUtc: nextUtc,
                    ErrorMessage: null,
                    NormalizedTimeZoneId: tz.Id,
                    Description: $"Runs every {intervalDuration.Value.TotalMinutes} minutes."
                );
            }

            if (scheduleType == ScheduleType.Cron)
            {
                var cron = CronExpression.Parse(cronExpression!, CronFormat.Standard);
                var nextUtc = cron.GetNextOccurrence(refUtc, tz);

                if (!nextUtc.HasValue)
                {
                    return new CampaignScheduleCalculationResult(
                        IsValid: false,
                        NextOccurrenceUtc: null,
                        ErrorMessage: "Cron expression produces no future occurrences.",
                        NormalizedTimeZoneId: tz.Id,
                        Description: null
                    );
                }

                return new CampaignScheduleCalculationResult(
                    IsValid: true,
                    NextOccurrenceUtc: nextUtc.Value,
                    ErrorMessage: null,
                    NormalizedTimeZoneId: tz.Id,
                    Description: $"Cron: '{cronExpression}' in timezone '{tz.Id}'."
                );
            }

            return new CampaignScheduleCalculationResult(
                IsValid: false,
                NextOccurrenceUtc: null,
                ErrorMessage: $"Unsupported schedule type '{scheduleType}'.",
                NormalizedTimeZoneId: timeZoneId,
                Description: null
            );
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Schedule calculation failed for ScheduleType: {Type}, Cron: '{Cron}', Interval: {Interval}, TZ: '{Tz}'.",
                scheduleType, cronExpression, intervalDuration, timeZoneId);

            return new CampaignScheduleCalculationResult(
                IsValid: false,
                NextOccurrenceUtc: null,
                ErrorMessage: ex.Message,
                NormalizedTimeZoneId: timeZoneId,
                Description: null
            );
        }
    }

    public void ValidateSchedule(
        ScheduleType scheduleType,
        string? cronExpression,
        TimeSpan? intervalDuration,
        string timeZoneId)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId))
        {
            throw new ArgumentException("TimeZoneId cannot be null or empty.", nameof(timeZoneId));
        }

        ResolveTimeZone(timeZoneId); // Will throw if invalid

        switch (scheduleType)
        {
            case ScheduleType.Interval:
                if (!intervalDuration.HasValue)
                {
                    throw new ArgumentException("IntervalDuration is required when ScheduleType is Interval.", nameof(intervalDuration));
                }

                if (intervalDuration.Value < MinimumInterval)
                {
                    throw new ArgumentException($"IntervalDuration must be at least {MinimumInterval.TotalMinutes} minutes (got {intervalDuration.Value.TotalMinutes} minutes).", nameof(intervalDuration));
                }

                if (!string.IsNullOrWhiteSpace(cronExpression))
                {
                    throw new ArgumentException("CronExpression must be null when ScheduleType is Interval.", nameof(cronExpression));
                }
                break;

            case ScheduleType.Cron:
                if (string.IsNullOrWhiteSpace(cronExpression))
                {
                    throw new ArgumentException("CronExpression is required when ScheduleType is Cron.", nameof(cronExpression));
                }

                if (intervalDuration.HasValue)
                {
                    throw new ArgumentException("IntervalDuration must be null when ScheduleType is Cron.", nameof(intervalDuration));
                }

                try
                {
                    CronExpression.Parse(cronExpression, CronFormat.Standard);
                }
                catch (CronFormatException ex)
                {
                    throw new ArgumentException($"Invalid Cron expression '{cronExpression}': {ex.Message}", nameof(cronExpression), ex);
                }
                break;

            default:
                throw new ArgumentException($"Unsupported ScheduleType '{scheduleType}'.", nameof(scheduleType));
        }
    }

    private static TimeZoneInfo ResolveTimeZone(string timeZoneId)
    {
        var normalized = timeZoneId.Trim();
        if (string.Equals(normalized, "UTC", StringComparison.OrdinalIgnoreCase))
        {
            return TimeZoneInfo.Utc;
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(normalized);
        }
        catch (TimeZoneNotFoundException ex)
        {
            throw new ArgumentException($"Timezone identifier '{timeZoneId}' was not recognized on this system.", nameof(timeZoneId), ex);
        }
        catch (InvalidTimeZoneException ex)
        {
            throw new ArgumentException($"Timezone identifier '{timeZoneId}' contains invalid data.", nameof(timeZoneId), ex);
        }
    }
}
