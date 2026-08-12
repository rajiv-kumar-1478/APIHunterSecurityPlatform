using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Adapters.AI;

public class GroqProviderAdapter : IAiProvider
{
    private readonly HttpClient _httpClient;
    private readonly IDataProtector _protector;
    private readonly AiProviderConfig _config;

    public string ProviderName => "Groq";

    public GroqProviderAdapter(HttpClient httpClient, IDataProtectionProvider protectionProvider, AiProviderConfig config)
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
            messages = new[]
            {
                new { role = "system", content = request.SystemPrompt },
                new { role = "user", content = request.UserPrompt }
            },
            temperature = request.Temperature,
            max_tokens = request.MaxTokens,
            response_format = request.RequireJsonOutput ? new { type = "json_object" } : null
        };

        var jsonBody = JsonSerializer.Serialize(payload);
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/chat/completions")
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
        };

        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rawApiKey);

        try
        {
            using var httpResponse = await _httpClient.SendAsync(httpRequest, ct);
            stopwatch.Stop();

            int? rateLimitRemaining = null;
            if (httpResponse.Headers.TryGetValues("x-ratelimit-remaining-requests", out var remValues) &&
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
                    ErrorMessage: $"Groq returned status code {(int)httpResponse.StatusCode} ({httpResponse.StatusCode}).",
                    IsRetryable: isRetryable,
                    RateLimitRemaining: rateLimitRemaining);
            }

            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            string contentText = string.Empty;
            if (root.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
            {
                var choice = choices[0];
                if (choice.TryGetProperty("message", out var msg) && msg.TryGetProperty("content", out var content))
                {
                    contentText = content.GetString() ?? string.Empty;
                }
            }

            int promptTokens = 0;
            int completionTokens = 0;
            if (root.TryGetProperty("usage", out var usage))
            {
                if (usage.TryGetProperty("prompt_tokens", out var pt)) promptTokens = pt.GetInt32();
                if (usage.TryGetProperty("completion_tokens", out var ctProp)) completionTokens = ctProp.GetInt32();
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
                ErrorMessage: "Groq request timed out or was cancelled.",
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
        if (statusCode == HttpStatusCode.NotFound || (statusCode == HttpStatusCode.BadRequest && responseBody.Contains("model_not_found", StringComparison.OrdinalIgnoreCase)))
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
