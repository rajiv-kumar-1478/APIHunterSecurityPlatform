namespace Platform.Domain.ValueObjects;

public record AiPromptRequest(
    string SystemPrompt,
    string UserPrompt,
    double Temperature = 0.1,
    int MaxTokens = 4000,
    bool RequireJsonOutput = true);

public record AiPromptResponse(
    bool IsSuccess,
    string RawResponseContent,
    string? NormalizedJsonContent,
    int PromptTokens,
    int CompletionTokens,
    string ProviderName,
    string ModelName,
    long LatencyMs,
    string? ErrorCode,
    string? ErrorMessage,
    bool IsRetryable,
    int? RateLimitRemaining = null,
    DateTime? RateLimitResetUtc = null);
