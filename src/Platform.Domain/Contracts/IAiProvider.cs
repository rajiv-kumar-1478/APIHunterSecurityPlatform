using Platform.Domain.ValueObjects;

namespace Platform.Domain.Contracts;

public interface IAiProvider
{
    string ProviderName { get; }
    Task<AiPromptResponse> CompletePromptAsync(AiPromptRequest request, CancellationToken ct = default);
    Task<AiHealthCheckResult> CheckHealthAsync(CancellationToken ct = default);
}

public record AiHealthCheckResult(bool IsHealthy, string StatusMessage, DateTime CheckedAtUtc);
