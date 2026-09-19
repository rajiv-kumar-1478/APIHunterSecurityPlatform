using System;
using System.IO;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Persistence;

/// <summary>
/// Direct proofs for the PostgreSQL error classifier.
///
/// The classifier decides whether the scheduler may reconcile a failed atomic dispatch as
/// SkippedClaimLost. Guessing here would either suppress real failures or duplicate scan
/// jobs, so both rules are asserted against constructed provider exceptions rather than
/// only through the PostgreSQL-gated integration suite.
/// </summary>
public sealed class PostgreSqlDatabaseErrorClassifierTests
{
    private const string OccurrenceConstraint = "IX_security_scan_jobs_campaign_occurrence_key";

    private readonly PostgreSqlDatabaseErrorClassifier _classifier = new();

    private static PostgresException CreatePostgresException(
        string sqlState,
        string? constraintName = null) => new(
            messageText: $"simulated PostgreSQL error {sqlState}",
            severity: "ERROR",
            invariantSeverity: "ERROR",
            sqlState: sqlState,
            constraintName: constraintName);

    // =========================================================================
    // Unique-constraint classification
    // =========================================================================

    [Fact]
    public void IsUniqueConstraintViolation_ExactConstraintWrappedByEf_ReturnsTrue()
    {
        var exception = new DbUpdateException(
            "An error occurred while saving the entity changes.",
            CreatePostgresException("23505", OccurrenceConstraint));

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeTrue();
    }

    [Fact]
    public void IsUniqueConstraintViolation_ExactConstraintSurfacedDirectly_ReturnsTrue()
    {
        var exception = CreatePostgresException("23505", OccurrenceConstraint);

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeTrue(
                "the provider can surface a constraint violation without EF's wrapper");
    }

    [Fact]
    public void IsUniqueConstraintViolation_DifferentConstraint_ReturnsFalse()
    {
        var exception = new DbUpdateException(
            "An error occurred while saving the entity changes.",
            CreatePostgresException("23505", "IX_some_other_unique_index"));

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeFalse(
                "another table's duplicate must never be read as this occurrence claim");
    }

    [Fact]
    public void IsUniqueConstraintViolation_UnnamedConstraint_ReturnsFalse()
    {
        var exception = CreatePostgresException("23505");

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeFalse("classification requires the exact constraint name");
    }

    [Theory]
    [InlineData("23514")] // check_violation
    [InlineData("23502")] // not_null_violation
    [InlineData("23503")] // foreign_key_violation
    public void IsUniqueConstraintViolation_OtherIntegrityFailures_ReturnFalse(string sqlState)
    {
        var exception = new DbUpdateException(
            "An error occurred while saving the entity changes.",
            CreatePostgresException(sqlState, OccurrenceConstraint));

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeFalse("only SQLSTATE 23505 is a unique violation");
    }

    [Fact]
    public void IsUniqueConstraintViolation_NonProviderException_ReturnsFalse()
    {
        var exception = new InvalidOperationException("unrelated failure");

        _classifier.IsUniqueConstraintViolation(exception, OccurrenceConstraint)
            .Should().BeFalse();
    }

    // =========================================================================
    // Ambiguous-commit classification
    // =========================================================================

    [Fact]
    public void IsPotentiallyAmbiguousCommitFailure_TransientConnectionLoss_ReturnsTrue()
    {
        var exception = new NpgsqlException(
            "Exception while writing to stream",
            new IOException("connection reset"));

        _classifier.IsPotentiallyAmbiguousCommitFailure(exception).Should().BeTrue(
            "a lost connection leaves the commit outcome unknown to the client");
    }

    [Fact]
    public void IsPotentiallyAmbiguousCommitFailure_TransientLossWrappedByEf_ReturnsTrue()
    {
        var exception = new DbUpdateException(
            "An error occurred while saving the entity changes.",
            new NpgsqlException(
                "Exception while writing to stream",
                new IOException("connection reset")));

        _classifier.IsPotentiallyAmbiguousCommitFailure(exception).Should().BeTrue();
    }

    [Theory]
    [InlineData("40001")] // serialization_failure — transient, but a definitive server answer
    [InlineData("40P01")] // deadlock_detected
    [InlineData("23505")] // unique_violation
    [InlineData("23514")] // check_violation
    public void IsPotentiallyAmbiguousCommitFailure_ServerResponses_ReturnFalse(string sqlState)
    {
        var direct = CreatePostgresException(sqlState);
        var wrapped = new DbUpdateException(
            "An error occurred while saving the entity changes.",
            CreatePostgresException(sqlState));

        _classifier.IsPotentiallyAmbiguousCommitFailure(direct).Should().BeFalse(
            "the server answered, so the commit outcome is known and must not be reconciled");
        _classifier.IsPotentiallyAmbiguousCommitFailure(wrapped).Should().BeFalse();
    }

    [Fact]
    public void IsPotentiallyAmbiguousCommitFailure_NonTransientProviderFailure_ReturnsFalse()
    {
        var exception = new NpgsqlException("malformed configuration");

        _classifier.IsPotentiallyAmbiguousCommitFailure(exception).Should().BeFalse();
    }

    [Fact]
    public void IsPotentiallyAmbiguousCommitFailure_UnrelatedException_ReturnsFalse()
    {
        var exception = new InvalidOperationException("application defect");

        _classifier.IsPotentiallyAmbiguousCommitFailure(exception).Should().BeFalse();
    }

    // =========================================================================
    // Argument validation
    // =========================================================================

    [Fact]
    public void Classifier_RejectsNullExceptionsAndBlankConstraintNames()
    {
        var validException = CreatePostgresException("23505", OccurrenceConstraint);

        ((Action)(() => _classifier.IsUniqueConstraintViolation(null!, OccurrenceConstraint)))
            .Should().Throw<ArgumentNullException>();
        ((Action)(() => _classifier.IsUniqueConstraintViolation(validException, "   ")))
            .Should().Throw<ArgumentException>();
        ((Action)(() => _classifier.IsPotentiallyAmbiguousCommitFailure(null!)))
            .Should().Throw<ArgumentNullException>();
    }
}
