namespace Platform.Application.Persistence;

/// <summary>
/// Classifies provider-specific database failures without coupling the application layer
/// to a concrete relational database driver.
/// </summary>
public interface IDatabaseErrorClassifier
{
    /// <summary>
    /// Returns true only when <paramref name="exception"/> represents a unique-constraint
    /// violation for the exact database constraint named by <paramref name="constraintName"/>.
    /// The provider may surface the failure directly or wrap it in an EF exception.
    /// </summary>
    bool IsUniqueConstraintViolation(Exception exception, string constraintName);

    /// <summary>
    /// Returns true when the provider reports a transient connection-level failure for
    /// which the client cannot know whether the database committed before acknowledgement.
    /// The provider may surface the failure directly or wrap it in an EF exception.
    /// Definitive server errors must return false.
    /// </summary>
    bool IsPotentiallyAmbiguousCommitFailure(Exception exception);
}
