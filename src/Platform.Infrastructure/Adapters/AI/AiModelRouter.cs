using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Adapters.AI;

public class AiModelRouter : IAiModelRouter
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IDataProtectionProvider _protectionProvider;
    private readonly ILogger<AiModelRouter> _logger;
    private readonly int _transientCooldownSeconds;

    public AiModelRouter(
        IPlatformDbContext dbContext,
        IHttpClientFactory httpClientFactory,
        IDataProtectionProvider protectionProvider,
        ILogger<AiModelRouter> logger,
        IOptions<AiRouterOptions>? options = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _protectionProvider = protectionProvider ?? throw new ArgumentNullException(nameof(protectionProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _transientCooldownSeconds = options?.Value?.TransientCooldownSeconds > 0
            ? options.Value.TransientCooldownSeconds
            : 120;
    }

    public async Task<IAiProvider> SelectBestProviderAsync(IEnumerable<string>? requiredCapabilities = null, CancellationToken ct = default)
    {
        var isGlobalEnabledSetting = await _dbContext.SystemSettings
            .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", ct);

        if (isGlobalEnabledSetting != null && string.Equals(isGlobalEnabledSetting.Value, "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("AI analysis is currently paused globally by Admin.");
        }

        var candidateConfigs = await LoadEligibleConfigsAsync(requiredCapabilities, ct);
        if (candidateConfigs.Count == 0)
        {
            throw new InvalidOperationException("No eligible or healthy AI provider configuration available.");
        }

        var bestConfig = candidateConfigs[0];
        return CreateProviderAdapter(bestConfig);
    }

    public async Task<(AiPromptResponse Response, string UsedProviderName, string UsedModelName)> ExecuteWithFallbackAsync(
        AiPromptRequest request,
        IEnumerable<string>? requiredCapabilities = null,
        CancellationToken ct = default)
    {
        var isGlobalEnabledSetting = await _dbContext.SystemSettings
            .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", ct);

        if (isGlobalEnabledSetting != null && string.Equals(isGlobalEnabledSetting.Value, "false", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("AI execution skipped: Global AI analysis is PAUSED by Admin.");
            return (new AiPromptResponse(
                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: "System",
                ModelName: "None",
                LatencyMs: 0,
                ErrorCode: "AiGloballyDisabled",
                ErrorMessage: "AI analysis is currently paused globally by Admin.",
                IsRetryable: false), "System", "None");
        }

        var eligibleConfigs = await LoadEligibleConfigsAsync(requiredCapabilities, ct);
        if (eligibleConfigs.Count == 0)
        {
            _logger.LogWarning("AI execution failed: No eligible provider configuration available.");
            return (new AiPromptResponse(
                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: "System",
                ModelName: "None",
                LatencyMs: 0,
                ErrorCode: "AllProvidersUnavailable",
                ErrorMessage: "No eligible, healthy, non-cooldown AI provider configuration available.",
                IsRetryable: true), "System", "None");
        }

        var attemptedConfigIds = new HashSet<Guid>();

        foreach (var config in eligibleConfigs)
        {
            if (attemptedConfigIds.Contains(config.Id)) continue;
            attemptedConfigIds.Add(config.Id);

            var adapter = CreateProviderAdapter(config);
            _logger.LogInformation("Routing AI request to Provider={Provider}, Model={Model}, Priority={Priority}", config.ProviderName, config.ModelName, config.Priority);

            var response = await adapter.CompletePromptAsync(request, ct);

            if (response.IsSuccess)
            {
                config.LastSuccessAtUtc = DateTime.UtcNow;
                config.TotalCallsCount++;
                config.HealthStatus = AiHealthStatus.Healthy;
                config.CooldownUntilUtc = null;
                config.RateLimitResetAtUtc = null;
                config.LastErrorReason = null;
                if (response.RateLimitRemaining.HasValue)
                {
                    config.RemainingQuota = response.RateLimitRemaining.Value;
                }

                await _dbContext.SaveChangesAsync(ct);
                return (response, config.ProviderName, config.ModelName);
            }

            config.FailedCallsCount++;
            config.LastFailureAtUtc = DateTime.UtcNow;
            config.LastErrorReason = response.ErrorMessage;

            if (response.ErrorCode == "RateLimited")
            {
                // Genuine Rate-Limit event -> set RateLimitResetAtUtc
                config.RateLimitResetAtUtc = DateTime.UtcNow.AddSeconds(_transientCooldownSeconds);
                config.HealthStatus = AiHealthStatus.RateLimited;
                _logger.LogWarning("Provider {Provider} rate limited. RateLimitResetAtUtc set to +{Seconds}s.", config.ProviderName, _transientCooldownSeconds);
            }
            else if (response.IsRetryable)
            {
                // Generic transient failure (Timeout, ProviderUnavailable, NetworkFailure) -> set CooldownUntilUtc
                config.CooldownUntilUtc = DateTime.UtcNow.AddSeconds(_transientCooldownSeconds);
                config.HealthStatus = AiHealthStatus.Degraded;
                _logger.LogWarning("Provider {Provider} transient failure ({ErrorCode}). CooldownUntilUtc set to +{Seconds}s.", config.ProviderName, response.ErrorCode, _transientCooldownSeconds);
            }
            else
            {
                // Non-retryable error (Auth failure, Invalid model, Invalid request) -> Mark Unreachable
                config.HealthStatus = AiHealthStatus.Unreachable;
                _logger.LogError("Provider {Provider} non-retryable failure ({ErrorCode}): {ErrorMessage}. Marked Unreachable.", config.ProviderName, response.ErrorCode, response.ErrorMessage);
            }

            await _dbContext.SaveChangesAsync(ct);

            if (response.ErrorCode == "AuthenticationFailure" || response.ErrorCode == "InvalidModelConfiguration" || response.ErrorCode == "InvalidRequest")
            {
                continue;
            }
        }

        return (new AiPromptResponse(
            IsSuccess: false,
            RawResponseContent: string.Empty,
            NormalizedJsonContent: null,
            PromptTokens: 0,
            CompletionTokens: 0,
            ProviderName: "System",
            ModelName: "None",
            LatencyMs: 0,
            ErrorCode: "AllProvidersUnavailable",
            ErrorMessage: "All available provider configurations failed to process the request.",
            IsRetryable: true), "System", "None");
    }

    public async Task<AiPromptResponse> TestProviderConfigAsync(AiProviderConfig config, CancellationToken ct = default)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        var adapter = CreateProviderAdapter(config);
        var testRequest = new AiPromptRequest(
            SystemPrompt: "Respond with valid JSON.",
            UserPrompt: "{\"ping\": \"pong\"}",
            RequireJsonOutput: true);

        return await adapter.CompletePromptAsync(testRequest, ct);
    }

    private async Task<List<AiProviderConfig>> LoadEligibleConfigsAsync(IEnumerable<string>? requiredCapabilities, CancellationToken ct)
    {
        var configs = await _dbContext.AiProviderConfigs
            .Where(p => p.IsEnabled)
            .OrderByDescending(p => p.Priority)
            .ToListAsync(ct);

        var now = DateTime.UtcNow;
        var eligible = new List<AiProviderConfig>();

        foreach (var c in configs)
        {
            if (string.IsNullOrWhiteSpace(c.EncryptedApiKey) || string.IsNullOrWhiteSpace(c.ModelName)) continue;
            if (c.HealthStatus == AiHealthStatus.Disabled || c.HealthStatus == AiHealthStatus.Unreachable) continue;

            // Check transient cooldown
            if (c.CooldownUntilUtc.HasValue && c.CooldownUntilUtc.Value > now) continue;

            // Check rate limit reset
            if (c.RateLimitResetAtUtc.HasValue && c.RateLimitResetAtUtc.Value > now) continue;

            if (requiredCapabilities != null && requiredCapabilities.Any())
            {
                var caps = ParseCapabilities(c.CapabilitiesJson);
                if (!requiredCapabilities.All(rc => caps.Contains(rc, StringComparer.OrdinalIgnoreCase)))
                {
                    continue;
                }
            }

            eligible.Add(c);
        }

        return eligible;
    }

    private IAiProvider CreateProviderAdapter(AiProviderConfig config)
    {
        var client = _httpClientFactory.CreateClient("AiProviderHttpClient");

        return config.ProviderName.ToUpperInvariant() switch
        {
            "OPENAI" => new OpenAiProviderAdapter(client, _protectionProvider, config),
            "ANTHROPIC" => new AnthropicProviderAdapter(client, _protectionProvider, config),
            "DEEPSEEK" => new DeepSeekProviderAdapter(client, _protectionProvider, config),
            "GROQ" => new GroqProviderAdapter(client, _protectionProvider, config),
            _ => new OpenAiProviderAdapter(client, _protectionProvider, config)
        };
    }

    private static List<string> ParseCapabilities(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<string>();
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
}
