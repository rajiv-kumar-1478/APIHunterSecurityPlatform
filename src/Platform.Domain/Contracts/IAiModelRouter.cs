using Platform.Domain.Entities;
using Platform.Domain.ValueObjects;

namespace Platform.Domain.Contracts;

public interface IAiModelRouter
{
    /// <summary>
    /// Selects the highest priority enabled, healthy, non-cooldown provider matching requested capabilities.
    /// Priority is dynamically read from the database registry (higher Priority integer = preferred).
    /// </summary>
    Task<IAiProvider> SelectBestProviderAsync(IEnumerable<string>? requiredCapabilities = null, CancellationToken ct = default);

    /// <summary>
    /// Executes a prompt using the best provider, cascading to next priority providers if a transient provider failure occurs.
    /// </summary>
    Task<(AiPromptResponse Response, string UsedProviderName, string UsedModelName)> ExecuteWithFallbackAsync(
        AiPromptRequest request,
        IEnumerable<string>? requiredCapabilities = null,
        CancellationToken ct = default);

    /// <summary>
    /// Executes an Admin connectivity test against a specific provider configuration.
    /// </summary>
    Task<AiPromptResponse> TestProviderConfigAsync(AiProviderConfig config, CancellationToken ct = default);
}
