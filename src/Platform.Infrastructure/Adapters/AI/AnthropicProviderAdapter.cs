using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Adapters.AI;

public class AnthropicProviderAdapter : IAiProvider
{
    private readonly HttpClient _httpClient;
    private readonly IDataProtector _protector;
    private readonly AiProviderConfig _config;

    public string ProviderName => "Anthropic";

    public AnthropicProviderAdapter(HttpClient httpClient, IDataProtectionProvider protectionProvider, AiProviderConfig config)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _protector = protectionProvider.CreateProtector("Platform.AiProvider.ApiKey");
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public async Task<AiPromptResponse> CompletePromptAsync(AiPromptRequest request, CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(_config.ModelName))
        {
            stopwatch.Stop();
            return new AiPromptResponse(
                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: ProviderName,
                ModelName: string.Empty,
                LatencyMs: stopwatch.ElapsedMilliseconds,
                ErrorCode: "InvalidModelConfiguration",
                ErrorMessage: "ModelName is not configured in provider configuration.",
                IsRetryable: false);
        }

        var modelName = _config.ModelName;

        string rawApiKey;
        try
        {
            rawApiKey = _protector.Unprotect(_config.EncryptedApiKey);
        }
        catch (Exception)
        {
            stopwatch.Stop();
            return new AiPromptResponse(
                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: ProviderName,
                ModelName: modelName,
                LatencyMs: stopwatch.ElapsedMilliseconds,
                ErrorCode: "AuthenticationError",
                ErrorMessage: "Failed to decrypt provider API key.",
                IsRetryable: false);
        }

        var payload = new
        {
            model = modelName,
            system = request.SystemPrompt,
            messages = new[]
            {
                new { role = "user", content = request.UserPrompt }
            },
            max_tokens = request.MaxTokens,
            temperature = request.Temperature
        };

        var jsonBody = JsonSerializer.Serialize(payload);
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
        };

        httpRequest.Headers.Add("x-api-key", rawApiKey);
        httpRequest.Headers.Add("anthropic-version", "2023-06-01");

        try
        {
            using var httpResponse = await _httpClient.SendAsync(httpRequest, ct);
            stopwatch.Stop();

            int? rateLimitRemaining = null;
            if (httpResponse.Headers.TryGetValues("anthropic-ratelimit-requests-remaining", out var remValues) &&
                int.TryParse(remValues.FirstOrDefault(), out var rem))
            {
                rateLimitRemaining = rem;
            }

            var responseBody = await httpResponse.Content.ReadAsStringAsync(ct);

            if (!httpResponse.IsSuccessStatusCode)
            {
                var (errorCode, isRetryable) = ClassifyHttpError(httpResponse.StatusCode, responseBody);
                return new AiPromptResponse(
                    IsSuccess: false,
                    RawResponseContent: responseBody,
                    NormalizedJsonContent: null,
                    PromptTokens: 0,
                    CompletionTokens: 0,
                    ProviderName: ProviderName,
                    ModelName: modelName,
                    LatencyMs: stopwatch.ElapsedMilliseconds,
                    ErrorCode: errorCode,
                    ErrorMessage: $"Anthropic returned status code {(int)httpResponse.StatusCode} ({httpResponse.StatusCode}).",
                    IsRetryable: isRetryable,
                    RateLimitRemaining: rateLimitRemaining);
            }

            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            string contentText = string.Empty;
            if (root.TryGetProperty("content", out var contentArray) && contentArray.GetArrayLength() > 0)
            {
                var firstBlock = contentArray[0];
                if (firstBlock.TryGetProperty("text", out var textProp))
                {
                    contentText = textProp.GetString() ?? string.Empty;
                }
            }

            int promptTokens = 0;
            int completionTokens = 0;
            if (root.TryGetProperty("usage", out var usage))
            {
                if (usage.TryGetProperty("input_tokens", out var pt)) promptTokens = pt.GetInt32();
                if (usage.TryGetProperty("output_tokens", out var ctProp)) completionTokens = ctProp.GetInt32();
            }

            return new AiPromptResponse(
                IsSuccess: true,
                RawResponseContent: responseBody,
                NormalizedJsonContent: contentText,
                PromptTokens: promptTokens,
                CompletionTokens: completionTokens,
                ProviderName: ProviderName,
                ModelName: modelName,
                LatencyMs: stopwatch.ElapsedMilliseconds,
                ErrorCode: null,
                ErrorMessage: null,
                IsRetryable: false,
                RateLimitRemaining: rateLimitRemaining);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            stopwatch.Stop();
            return new AiPromptResponse(
                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: ProviderName,
                ModelName: modelName,
                LatencyMs: stopwatch.ElapsedMilliseconds,
                ErrorCode: "Timeout",
                ErrorMessage: "Anthropic request timed out or was cancelled.",
                IsRetryable: true);
        }
        catch (Exception)
        {
            stopwatch.Stop();
            return new AiPromptResponse(

                IsSuccess: false,
                RawResponseContent: string.Empty,
                NormalizedJsonContent: null,
                PromptTokens: 0,
                CompletionTokens: 0,
                ProviderName: ProviderName,
                ModelName: modelName,
                LatencyMs: stopwatch.ElapsedMilliseconds,
                ErrorCode: "NetworkFailure",
                ErrorMessage: $"Network exception occurred while contacting provider.",
                IsRetryable: true);
        }
    }

    public Task<AiHealthCheckResult> CheckHealthAsync(CancellationToken ct = default)
    {
        if (!_config.IsEnabled)
        {
            return Task.FromResult(new AiHealthCheckResult(false, "Provider is disabled.", DateTime.UtcNow));
        }

        if (string.IsNullOrWhiteSpace(_config.ModelName))
        {
            return Task.FromResult(new AiHealthCheckResult(false, "ModelName is not configured.", DateTime.UtcNow));
        }

        if (string.IsNullOrWhiteSpace(_config.EncryptedApiKey))
        {
            return Task.FromResult(new AiHealthCheckResult(false, "API key is not configured.", DateTime.UtcNow));
        }

        return Task.FromResult(new AiHealthCheckResult(true, "Configuration valid and active.", DateTime.UtcNow));
    }

    private static (string ErrorCode, bool IsRetryable) ClassifyHttpError(HttpStatusCode statusCode, string responseBody)
    {
        if (statusCode == HttpStatusCode.NotFound || (statusCode == HttpStatusCode.BadRequest && responseBody.Contains("not_found", StringComparison.OrdinalIgnoreCase)))
        {
            return ("ModelUnavailable", false);
        }

        return statusCode switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => ("AuthenticationFailure", false),
            HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => ("InvalidRequest", false),
            HttpStatusCode.TooManyRequests => ("RateLimited", true),
            HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout => ("ProviderUnavailable", true),
            _ => ("UnknownProviderError", true)
        };
    }
}
