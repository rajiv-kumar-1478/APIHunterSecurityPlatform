using Npgsql;
using Platform.Application.Persistence;

namespace Platform.Infrastructure.Persistence;

/// <summary>
/// Classifies PostgreSQL failures using stable SQLSTATE and constraint metadata.
/// </summary>
public sealed class PostgreSqlDatabaseErrorClassifier : IDatabaseErrorClassifier
{
    public bool IsUniqueConstraintViolation(Exception exception, string constraintName)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentException.ThrowIfNullOrWhiteSpace(constraintName);

        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is PostgresException postgresException)
            {
                return postgresException.SqlState == PostgresErrorCodes.UniqueViolation
                    && string.Equals(
                        postgresException.ConstraintName,
                        constraintName,
                        StringComparison.Ordinal);
            }
        }

        return false;
    }

    public bool IsPotentiallyAmbiguousCommitFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        // A PostgresException is a definitive server response, not an unknown commit outcome.
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is PostgresException)
            {
                return false;
            }
        }

        // Npgsql may surface a connection failure directly when transaction commit or its
        // acknowledgement fails, rather than wrapping it in DbUpdateException.
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is NpgsqlException npgsqlException && npgsqlException.IsTransient)
            {
                return true;
            }
        }

        return false;
    }
}
