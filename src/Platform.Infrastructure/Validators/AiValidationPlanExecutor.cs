using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Platform.Application.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

/// <summary>
/// Executes an AI-proposed validation plan against a server-controlled allowlisted provider
/// origin. The plan may choose the path, method and authentication scheme, but it can never
/// change the destination host or place the secret in the URL.
/// </summary>
public sealed class AiValidationPlanExecutor(
    SsrfProtectionService ssrfProtectionService,
    ValidationEndpointRegistry endpointRegistry,
    ILogger<AiValidationPlanExecutor> logger) : IAiValidationPlanExecutor
{
    private static readonly (string Token, string Provider)[] ProviderAliases =
    [
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic"),
        ("claude", "Anthropic"),
        ("github", "GitHub"),
        ("aws", "AWSIAM"),
        ("amazon", "AWSIAM"),
        ("stripe", "Stripe"),
        ("sendgrid", "SendGrid"),
        ("mailgun", "Mailgun"),
        ("deepseek", "DeepSeek"),
        ("groq", "Groq"),
        ("slack", "Slack"),
        ("huggingface", "HuggingFace"),
        ("perplexity", "Perplexity"),
        ("cohere", "Cohere"),
        ("fireworks", "FireworksAI"),
        ("replicate", "Replicate"),
        ("openrouter", "OpenRouter"),
        ("xai", "XAI"),
        ("grok", "XAI"),
        ("cerebras", "Cerebras"),
        ("tavily", "Tavily"),
        ("fal", "FalAi"),
        ("jina", "JinaAI"),
        ("kling", "KlingAI"),
        ("runway", "RunwayML"),
        ("runpod", "RunPod"),
        ("gemini", "GoogleGemini"),
        ("elevenlabs", "ElevenLabs"),
        ("together", "TogetherAI"),
        ("mistral", "Mistral"),
        ("stability", "StabilityAI"),
        ("ai21", "AI21"),
        ("assemblyai", "AssemblyAI"),
        ("deepgram", "Deepgram"),
        ("leonardo", "LeonardoAI")
    ];

    public async Task<ValidationResultDto> ExecuteAsync(
        string providerName,
        AiValidationPlan plan,
        string decryptedSecret,
        CancellationToken ct = default)
    {
        if (plan is null)
            return Error("AI validation plan is missing.");

        if (string.IsNullOrWhiteSpace(decryptedSecret))
            return new ValidationResultDto(
                ValidationStatus.ValidationError,
                ValidationConfidence.Indeterminate,
                "Secret could not be decrypted for validation.",
                "{}",
                0);

        if (!string.IsNullOrWhiteSpace(plan.Url) &&
            plan.Url.Contains("{{SECRET}}", StringComparison.Ordinal))
        {
            return Error("AI validation plan attempted to place the secret in the URL; rejected.");
        }

        if (string.Equals(plan.AuthType, "query", StringComparison.OrdinalIgnoreCase))
            return Error("Query-parameter authentication is not permitted for AI validation plans.");

        var resolvedProvider = ResolveProvider(providerName);
        if (resolvedProvider is null)
        {
            return new ValidationResultDto(
                ValidationStatus.Unsupported,
                ValidationConfidence.Indeterminate,
                $"Provider '{providerName}' is not allowlisted for validation.",
                "{}",
                0);
        }

        var origin = endpointRegistry.GetAllowlistedEndpoint(resolvedProvider);
        var requestUri = BuildRequestUri(origin, plan.Url);
        if (requestUri is null)
            return Error("AI validation plan URL could not be mapped to the allowlisted provider origin.");

        if (!TryMapAuthScheme(plan, out var scheme, out var headerName))
        {
            return new ValidationResultDto(
                ValidationStatus.Unsupported,
                ValidationConfidence.Indeterminate,
                $"AI validation plan auth type '{plan.AuthType}' is not supported.",
                "{}",
                0);
        }

        var descriptor = new ProviderValidationDescriptor
        {
            RequestUri = requestUri.AbsoluteUri,
            AuthScheme = scheme,
            AuthHeaderName = headerName,
            Method = string.Equals(plan.Method, "POST", StringComparison.OrdinalIgnoreCase)
                ? HttpMethod.Post
                : HttpMethod.Get,
            SuccessJsonProperty = NormalizeJsonPath(plan.SuccessJsonPath),
            SuccessLabel = $"AI validation plan for {resolvedProvider}"
        };

        var stopwatch = Stopwatch.StartNew();
        try
        {
            var handler = ssrfProtectionService.CreatePinnedSsrfHandler(resolvedProvider);
            using var client = new HttpClient(handler, disposeHandler: true);
            return await ProviderValidationExecutor.ExecuteAsync(client, descriptor, decryptedSecret, stopwatch, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            logger.LogWarning(ex, "AI validation plan execution failed for provider '{Provider}'.", resolvedProvider);
            return new ValidationResultDto(
                ValidationStatus.ValidationError,
                ValidationConfidence.Indeterminate,
                $"AI plan execution failed: {ex.Message}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }
    }

    private string? ResolveProvider(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
            return null;

        if (endpointRegistry.IsProviderSupported(providerName))
            return providerName;

        var normalized = providerName
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);

        foreach (var (token, provider) in ProviderAliases)
        {
            if (normalized.Contains(token, StringComparison.OrdinalIgnoreCase) &&
                endpointRegistry.IsProviderSupported(provider))
            {
                return provider;
            }
        }

        foreach (var supported in endpointRegistry.SupportedProviders)
        {
            if (normalized.Contains(supported, StringComparison.OrdinalIgnoreCase))
                return supported;
        }

        return null;
    }

    private static Uri? BuildRequestUri(Uri origin, string? planUrl)
    {
        if (string.IsNullOrWhiteSpace(planUrl))
            return origin;

        if (!Uri.TryCreate(planUrl, UriKind.Absolute, out var parsed))
        {
            var relative = planUrl.StartsWith('/') ? planUrl : "/" + planUrl;
            return Uri.TryCreate(origin, relative, out var combined) ? combined : null;
        }

        return Uri.TryCreate(origin, parsed.PathAndQuery, out var mapped) ? mapped : null;
    }

    private static bool TryMapAuthScheme(
        AiValidationPlan plan,
        out ProviderAuthScheme scheme,
        out string? headerName)
    {
        headerName = plan.AuthHeaderName;

        switch ((plan.AuthType ?? "bearer").Trim().ToLowerInvariant())
        {
            case "bearer":
                scheme = ProviderAuthScheme.BearerAuthorization;
                return true;

            case "token":
                scheme = ProviderAuthScheme.TokenAuthorization;
                return true;

            case "key":
                scheme = ProviderAuthScheme.KeyAuthorization;
                return true;

            case "raw":
            case "authorization":
                scheme = ProviderAuthScheme.RawAuthorization;
                return true;

            case "header":
            case "custom":
                scheme = ProviderAuthScheme.CustomHeader;
                headerName ??= "Authorization";
                return !string.IsNullOrWhiteSpace(headerName);

            case "none":
                scheme = ProviderAuthScheme.None;
                return true;

            default:
                scheme = default;
                return false;
        }
    }

    private static string? NormalizeJsonPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        var normalized = path.Trim();
        if (normalized.StartsWith("$.", StringComparison.Ordinal))
            normalized = normalized[2..];
        else if (normalized.StartsWith('$'))
            normalized = normalized[1..];

        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static ValidationResultDto Error(string message) =>
        new(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, message, "{}", 0);
}
