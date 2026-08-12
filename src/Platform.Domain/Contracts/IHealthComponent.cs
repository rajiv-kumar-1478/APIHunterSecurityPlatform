namespace Platform.Domain.Contracts;

/// <summary>
/// Abstraction for a health-checkable platform component.
/// Phase 1 registers: ApiHealthComponent, PostgresHealthComponent.
/// Future phases plug in: EmailProvider, Queue, R2, AI, BugHunter, etc.
/// </summary>
public interface IHealthComponent
{
    string ComponentName { get; }
    Task<ComponentHealthResult> CheckAsync(CancellationToken cancellationToken = default);
}

public record ComponentHealthResult(
    string ComponentName,
    bool IsHealthy,
    string Status,
    string? Detail = null,
    TimeSpan? Latency = null);
