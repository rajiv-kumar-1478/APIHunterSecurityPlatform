namespace Platform.Domain.ValueObjects;

/// <summary>
/// Result of a provider health check operation.
/// </summary>
public record ProviderHealthResult(
    string ProviderName,
    bool IsHealthy,
    string Status,
    string? Detail = null,
    TimeSpan? Latency = null);
