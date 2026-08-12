using System.Net;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Moq;
using Moq.Protected;
using Platform.Domain.Entities;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Adapters.AI;
using Xunit;

namespace Platform.UnitTests.Adapters;

public class AiProviderAdapterTests
{
    private readonly IDataProtectionProvider _protectionProvider;
    private readonly string _encryptedApiKey;
    private const string RawApiKey = "sk-test-secret-api-key-12345";

    public AiProviderAdapterTests()
    {
        _protectionProvider = new EphemeralDataProtectionProvider();
        var protector = _protectionProvider.CreateProtector("Platform.AiProvider.ApiKey");
        _encryptedApiKey = protector.Protect(RawApiKey);
    }

    private static HttpClient CreateMockHttpClient(HttpStatusCode statusCode, string responseContent, Dictionary<string, string>? headers = null)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        var httpResponse = new HttpResponseMessage
        {
            StatusCode = statusCode,
            Content = new StringContent(responseContent, Encoding.UTF8, "application/json")
        };

        if (headers != null)
        {
            foreach (var (key, value) in headers)
            {
                httpResponse.Headers.TryAddWithoutValidation(key, value);
            }
        }

        handlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(httpResponse);

        return new HttpClient(handlerMock.Object);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OpenAI Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task OpenAi_Success_NormalizesResponseAndUsage()
    {
        var jsonResponse = """
        {
            "choices": [ { "message": { "content": "{\"finding\": \"PostgreSQL DB\"}" } } ],
            "usage": { "prompt_tokens": 150, "completion_tokens": 42 }
        }
        """;
        var client = CreateMockHttpClient(HttpStatusCode.OK, jsonResponse, new() { { "x-ratelimit-remaining-requests", "4950" } });
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "gpt-4o", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var request = new AiPromptRequest("System Prompt", "User Prompt");
        var response = await adapter.CompletePromptAsync(request);

        Assert.True(response.IsSuccess);
        Assert.Equal("OpenAI", response.ProviderName);
        Assert.Equal("gpt-4o", response.ModelName);
        Assert.Equal("{\"finding\": \"PostgreSQL DB\"}", response.NormalizedJsonContent);
        Assert.Equal(150, response.PromptTokens);
        Assert.Equal(42, response.CompletionTokens);
        Assert.Equal(4950, response.RateLimitRemaining);
        Assert.False(response.IsRetryable);
    }

    [Fact]
    public async Task OpenAi_AuthFailure_ReturnsNonRetryableError()
    {
        var client = CreateMockHttpClient(HttpStatusCode.Unauthorized, "{\"error\": \"Invalid API Key\"}");
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "gpt-4o", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("AuthenticationFailure", response.ErrorCode);
        Assert.False(response.IsRetryable);
        Assert.DoesNotContain(RawApiKey, response.ErrorMessage);
    }

    [Fact]
    public async Task OpenAi_RateLimited_ReturnsRetryableError()
    {
        var client = CreateMockHttpClient(HttpStatusCode.TooManyRequests, "{\"error\": \"Rate limit reached\"}");
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "gpt-4o", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("RateLimited", response.ErrorCode);
        Assert.True(response.IsRetryable);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Anthropic Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Anthropic_Success_NormalizesResponseAndUsage()
    {
        var jsonResponse = """
        {
            "content": [ { "type": "text", "text": "{\"finding\": \"AWS Key\"}" } ],
            "usage": { "input_tokens": 200, "output_tokens": 50 }
        }
        """;
        var client = CreateMockHttpClient(HttpStatusCode.OK, jsonResponse, new() { { "anthropic-ratelimit-requests-remaining", "980" } });
        var config = new AiProviderConfig { ProviderName = "Anthropic", ModelName = "claude-3-5-sonnet-20241022", EncryptedApiKey = _encryptedApiKey };
        var adapter = new AnthropicProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.True(response.IsSuccess);
        Assert.Equal("Anthropic", response.ProviderName);
        Assert.Equal("claude-3-5-sonnet-20241022", response.ModelName);
        Assert.Equal("{\"finding\": \"AWS Key\"}", response.NormalizedJsonContent);
        Assert.Equal(200, response.PromptTokens);
        Assert.Equal(50, response.CompletionTokens);
        Assert.Equal(980, response.RateLimitRemaining);
    }

    [Fact]
    public async Task Anthropic_AuthFailure_ReturnsNonRetryableError()
    {
        var client = CreateMockHttpClient(HttpStatusCode.Forbidden, "{\"error\": \"Forbidden\"}");
        var config = new AiProviderConfig { ProviderName = "Anthropic", ModelName = "claude-3-5-sonnet-20241022", EncryptedApiKey = _encryptedApiKey };
        var adapter = new AnthropicProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("AuthenticationFailure", response.ErrorCode);
        Assert.False(response.IsRetryable);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeepSeek Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeepSeek_Success_NormalizesResponse()
    {
        var jsonResponse = """
        {
            "choices": [ { "message": { "content": "{\"finding\": \"DeepSeek Secret\"}" } } ],
            "usage": { "prompt_tokens": 100, "completion_tokens": 30 }
        }
        """;
        var client = CreateMockHttpClient(HttpStatusCode.OK, jsonResponse);
        var config = new AiProviderConfig { ProviderName = "DeepSeek", ModelName = "deepseek-chat", EncryptedApiKey = _encryptedApiKey };
        var adapter = new DeepSeekProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.True(response.IsSuccess);
        Assert.Equal("DeepSeek", response.ProviderName);
        Assert.Equal("deepseek-chat", response.ModelName);
        Assert.Equal("{\"finding\": \"DeepSeek Secret\"}", response.NormalizedJsonContent);
    }

    [Fact]
    public async Task DeepSeek_ServiceUnavailable_ReturnsRetryableError()
    {
        var client = CreateMockHttpClient(HttpStatusCode.ServiceUnavailable, "Service Unavailable");
        var config = new AiProviderConfig { ProviderName = "DeepSeek", ModelName = "deepseek-chat", EncryptedApiKey = _encryptedApiKey };
        var adapter = new DeepSeekProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("ProviderUnavailable", response.ErrorCode);
        Assert.True(response.IsRetryable);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Groq Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Groq_Success_NormalizesResponse()
    {
        var jsonResponse = """
        {
            "choices": [ { "message": { "content": "{\"finding\": \"Llama Secret\"}" } } ],
            "usage": { "prompt_tokens": 80, "completion_tokens": 20 }
        }
        """;
        var client = CreateMockHttpClient(HttpStatusCode.OK, jsonResponse);
        var config = new AiProviderConfig { ProviderName = "Groq", ModelName = "llama-3.3-70b-versatile", EncryptedApiKey = _encryptedApiKey };
        var adapter = new GroqProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.True(response.IsSuccess);
        Assert.Equal("Groq", response.ProviderName);
        Assert.Equal("llama-3.3-70b-versatile", response.ModelName);
        Assert.Equal("{\"finding\": \"Llama Secret\"}", response.NormalizedJsonContent);
    }

    [Fact]
    public async Task Groq_RateLimited_ReturnsRetryableError()
    {
        var client = CreateMockHttpClient(HttpStatusCode.TooManyRequests, "Rate Limited");
        var config = new AiProviderConfig { ProviderName = "Groq", ModelName = "llama-3.3-70b-versatile", EncryptedApiKey = _encryptedApiKey };
        var adapter = new GroqProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("RateLimited", response.ErrorCode);
        Assert.True(response.IsRetryable);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Model Availability & Security Corrections Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ModelAvailability_UnconfiguredModel_FailsFastWithInvalidModelConfiguration()
    {
        var client = CreateMockHttpClient(HttpStatusCode.OK, "{}");
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("InvalidModelConfiguration", response.ErrorCode);
        Assert.False(response.IsRetryable);
    }

    [Fact]
    public async Task ModelAvailability_NotFoundHttpError_ClassifiedAsModelUnavailable()
    {
        var client = CreateMockHttpClient(HttpStatusCode.NotFound, "{\"error\": {\"code\": \"model_not_found\"}}");
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "non-existent-model", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.Equal("ModelUnavailable", response.ErrorCode);
        Assert.False(response.IsRetryable);
    }

    [Fact]
    public async Task RawResponseSecurity_SensitiveContentInResponseBody_NotExposedInErrorMessage()
    {
        var sensitiveBody = "{\"error\": \"Failed at line 5: super_secret_db_password_99\"}";
        var client = CreateMockHttpClient(HttpStatusCode.BadRequest, sensitiveBody);
        var config = new AiProviderConfig { ProviderName = "OpenAI", ModelName = "gpt-4o", EncryptedApiKey = _encryptedApiKey };
        var adapter = new OpenAiProviderAdapter(client, _protectionProvider, config);

        var response = await adapter.CompletePromptAsync(new AiPromptRequest("System", "User"));

        Assert.False(response.IsSuccess);
        Assert.DoesNotContain("super_secret_db_password_99", response.ErrorMessage);
    }

    [Fact]
    public async Task AllAdapters_NeverExposeRawApiKeyInResponseOrErrorMessages()
    {
        var client = CreateMockHttpClient(HttpStatusCode.InternalServerError, "Error body with no key");
        var config = new AiProviderConfig { EncryptedApiKey = _encryptedApiKey, ModelName = "test-model" };

        var openAi = new OpenAiProviderAdapter(client, _protectionProvider, config);
        var anthropic = new AnthropicProviderAdapter(client, _protectionProvider, config);
        var deepSeek = new DeepSeekProviderAdapter(client, _protectionProvider, config);
        var groq = new GroqProviderAdapter(client, _protectionProvider, config);

        var request = new AiPromptRequest("Sys", "Usr");
        var res1 = await openAi.CompletePromptAsync(request);
        var res2 = await anthropic.CompletePromptAsync(request);
        var res3 = await deepSeek.CompletePromptAsync(request);
        var res4 = await groq.CompletePromptAsync(request);

        foreach (var res in new[] { res1, res2, res3, res4 })
        {
            Assert.DoesNotContain(RawApiKey, res.ErrorMessage ?? string.Empty);
            Assert.DoesNotContain(RawApiKey, res.RawResponseContent);
        }
    }
}
