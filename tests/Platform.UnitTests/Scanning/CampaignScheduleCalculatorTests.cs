using System;
using FluentAssertions;
using Platform.Application.Services;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class CampaignScheduleCalculatorTests
{
    private readonly CampaignScheduleCalculator _calculator = new();

    // =========================================================================
    // 1. INTERVAL SCHEDULE VALIDATIONS & OCCURRENCE CALCULATIONS
    // =========================================================================

    [Fact]
    public void Interval_ValidDuration_CalculatesNextUtcCorrectly()
    {
        var refUtc = new DateTime(2026, 8, 14, 12, 0, 0, DateTimeKind.Utc);
        var interval = TimeSpan.FromHours(6);

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Interval,
            cronExpression: null,
            intervalDuration: interval,
            timeZoneId: "UTC",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeTrue();
        result.NextOccurrenceUtc.Should().Be(new DateTime(2026, 8, 14, 18, 0, 0, DateTimeKind.Utc));
        result.ErrorMessage.Should().BeNull();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(14)]
    public void Interval_Under15Minutes_IsRejected(int minutes)
    {
        var refUtc = DateTime.UtcNow;
        var interval = TimeSpan.FromMinutes(minutes);

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Interval,
            cronExpression: null,
            intervalDuration: interval,
            timeZoneId: "UTC",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeFalse();
        result.NextOccurrenceUtc.Should().BeNull();
        result.ErrorMessage.Should().Contain("at least 15 minutes");
    }

    [Fact]
    public void Interval_WithCronExpressionProvided_ThrowsValidationException()
    {
        var refUtc = DateTime.UtcNow;

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Interval,
            cronExpression: "0 0 * * *",
            intervalDuration: TimeSpan.FromHours(1),
            timeZoneId: "UTC",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("CronExpression must be null");
    }

    // =========================================================================
    // 2. CRON SCHEDULE VALIDATIONS & TIMEZONE EVALUATION
    // =========================================================================

    [Fact]
    public void Cron_DailyMidnightUtc_CalculatesNextDayMidnight()
    {
        var refUtc = new DateTime(2026, 8, 14, 14, 30, 0, DateTimeKind.Utc);
        var cron = "0 0 * * *"; // Midnight UTC

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Cron,
            cronExpression: cron,
            intervalDuration: null,
            timeZoneId: "UTC",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeTrue();
        result.NextOccurrenceUtc.Should().Be(new DateTime(2026, 8, 15, 0, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void Cron_WithIanaTimezone_CalculatesAccurateUtcEquivalent()
    {
        // 2:00 AM in Asia/Kolkata (UTC +5:30) on Aug 15 = Aug 14 20:30 UTC
        var refUtc = new DateTime(2026, 8, 14, 10, 0, 0, DateTimeKind.Utc);
        var cron = "0 2 * * *"; // 2:00 AM IST

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Cron,
            cronExpression: cron,
            intervalDuration: null,
            timeZoneId: "Asia/Kolkata",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeTrue();
        result.NextOccurrenceUtc.Should().Be(new DateTime(2026, 8, 14, 20, 30, 0, DateTimeKind.Utc));
    }

    [Theory]
    [InlineData("invalid-cron")]
    [InlineData("* * *")] // Only 3 parts
    [InlineData("65 * * * *")] // Minute 65 invalid
    public void Cron_MalformedExpression_IsRejected(string invalidCron)
    {
        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Cron,
            cronExpression: invalidCron,
            intervalDuration: null,
            timeZoneId: "UTC",
            referenceTimeUtc: DateTime.UtcNow
        );

        result.IsValid.Should().BeFalse();
        result.NextOccurrenceUtc.Should().BeNull();
        result.ErrorMessage.Should().NotBeNull();
    }

    [Fact]
    public void InvalidTimezone_IsRejected()
    {
        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Cron,
            cronExpression: "0 0 * * *",
            intervalDuration: null,
            timeZoneId: "NonExistent/InvalidZone",
            referenceTimeUtc: DateTime.UtcNow
        );

        result.IsValid.Should().BeFalse();
        result.ErrorMessage.Should().Contain("was not recognized");
    }

    // =========================================================================
    // 3. DST TRANSITION EVALUATION
    // =========================================================================

    [Fact]
    public void Cron_AmericaNewYork_SpringForwardTransition_EvaluatesCorrectly()
    {
        // US Eastern spring forward in 2026: March 8 at 2:00 AM jumps to 3:00 AM
        // Cron: 2:30 AM every day
        var refUtc = new DateTime(2026, 3, 7, 12, 0, 0, DateTimeKind.Utc);
        var cron = "30 2 * * *";

        var result = _calculator.CalculateNextOccurrence(
            ScheduleType.Cron,
            cronExpression: cron,
            intervalDuration: null,
            timeZoneId: "America/New_York",
            referenceTimeUtc: refUtc
        );

        result.IsValid.Should().BeTrue();
        result.NextOccurrenceUtc.Should().NotBeNull();
    }
}
