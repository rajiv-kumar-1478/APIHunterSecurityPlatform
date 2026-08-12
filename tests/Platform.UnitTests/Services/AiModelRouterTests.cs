using System.Net;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Adapters.AI;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class AiModelRouterTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly IDataProtectionProvider _protectionProvider;
    private readonly string _encryptedKey1;
    private readonly string _encryptedKey2;
    private readonly Mock<IHttpClientFactory> _mockClientFactory;
    private readonly Mock<ILogger<AiModelRouter>> _mockLogger;

    public AiModelRouterTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiModelRouterTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _protectionProvider = new EphemeralDataProtectionProvider();
        var protector = _protectionProvider.CreateProtector("Platform.AiProvider.ApiKey");
        _encryptedKey1 = protector.Protect("sk-test-key-1111");
        _encryptedKey2 = protector.Protect("sk-test-key-2222");

        _mockClientFactory = new Mock<IHttpClientFactory>();
        _mockLogger = new Mock<ILogger<AiModelRouter>>();
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private static HttpClient CreateMockHttpClient(HttpStatusCode statusCode, string responseContent)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        var httpResponse = new HttpResponseMessage
        {
            StatusCode = statusCode,
            Content = new StringContent(responseContent, Encoding.UTF8, "application/json")
        };

        handlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(httpResponse);

        return new HttpClient(handlerMock.Object);
    }

    [Fact]
    public async Task Router_SelectsHighestPriorityEnabledHealthyProvider()
    {
        var deepSeek = new AiProviderConfig
        {
            ProviderName = "DeepSeek",
            ModelName = "deepseek-chat",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1,
            HealthStatus = AiHealthStatus.Healthy
        };

        var groq = new AiProviderConfig
        {
            ProviderName = "Groq",
            ModelName = "llama-3.3-70b-versatile",
            Priority = 90,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey2,
            HealthStatus = AiHealthStatus.Healthy
        };

        _dbContext.AiProviderConfigs.AddRange(deepSeek, groq);
        await _dbContext.SaveChangesAsync();

        var successJson = """
        {
            "choices": [ { "message": { "content": "{\"finding\": \"DeepSeek Secret\"}" } } ],
            "usage": { "prompt_tokens": 50, "completion_tokens": 10 }
        }
        """;
        _mockClientFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(CreateMockHttpClient(HttpStatusCode.OK, successJson));

        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object);
        var (response, usedProvider, usedModel) = await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        Assert.True(response.IsSuccess);
        Assert.Equal("DeepSeek", usedProvider);
        Assert.Equal("deepseek-chat", usedModel);
    }

    [Fact]
    public async Task AuthenticationFailure_MarksProviderUnreachable()
    {
        var provider = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1,
            HealthStatus = AiHealthStatus.Healthy
        };

        _dbContext.AiProviderConfigs.Add(provider);
        await _dbContext.SaveChangesAsync();

        _mockClientFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(CreateMockHttpClient(HttpStatusCode.Unauthorized, "{\"error\": \"Invalid API Key\"}"));

        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object);
        var (response, _, _) = await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        Assert.False(response.IsSuccess);
        Assert.Equal("AllProvidersUnavailable", response.ErrorCode);

        var updated = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == provider.Id);
        Assert.Equal(AiHealthStatus.Unreachable, updated.HealthStatus);

    }

    [Fact]
    public async Task TransientCooldown_ExpiredCooldown_AllowsProviderSelectionAgain()
    {
        var expiredCooldown = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1,
            HealthStatus = AiHealthStatus.Degraded,
            CooldownUntilUtc = DateTime.UtcNow.AddMinutes(-1) // Expired 1 minute ago
        };

        _dbContext.AiProviderConfigs.Add(expiredCooldown);
        await _dbContext.SaveChangesAsync();

        _mockClientFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(CreateMockHttpClient(HttpStatusCode.OK, """{"choices":[{"message":{"content":"ok"}}]}"""));

        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object);
        var (response, usedProvider, _) = await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        Assert.True(response.IsSuccess);
        Assert.Equal("OpenAI", usedProvider);
    }

    [Fact]
    public async Task RateLimitReset_HandledSeparatelyFromGenericCooldown()
    {
        var rateLimited = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1,
            HealthStatus = AiHealthStatus.Healthy
        };

        _dbContext.AiProviderConfigs.Add(rateLimited);
        await _dbContext.SaveChangesAsync();

        _mockClientFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(CreateMockHttpClient(HttpStatusCode.TooManyRequests, "Rate Limited"));

        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object);
        await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        var updated = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == rateLimited.Id);
        Assert.Equal(AiHealthStatus.RateLimited, updated.HealthStatus);
        Assert.NotNull(updated.RateLimitResetAtUtc);
        Assert.Null(updated.CooldownUntilUtc); // Rate limit reset is separate from generic cooldown
    }

    [Fact]
    public async Task ConfigurableCooldownSeconds_RespectedByRouter()
    {
        var provider = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1
        };

        _dbContext.AiProviderConfigs.Add(provider);
        await _dbContext.SaveChangesAsync();

        _mockClientFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(CreateMockHttpClient(HttpStatusCode.ServiceUnavailable, "Service Unavailable"));

        var options = Options.Create(new AiRouterOptions { TransientCooldownSeconds = 300 });
        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object, options);
        
        await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        var updated = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == provider.Id);
        Assert.NotNull(updated.CooldownUntilUtc);
        Assert.True(updated.CooldownUntilUtc.Value > DateTime.UtcNow.AddSeconds(290));
    }

    [Fact]
    public async Task Router_RespectsGlobalPauseStateAndDoesNotCallProvider()
    {
        var providerConfig = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            Priority = 100,
            IsEnabled = true,
            EncryptedApiKey = _encryptedKey1
        };

        _dbContext.AiProviderConfigs.Add(providerConfig);
        _dbContext.SystemSettings.Add(new SystemSetting { Key = "ai.global_enabled", Value = "false", ValueType = SettingValueType.Boolean });
        await _dbContext.SaveChangesAsync();

        var router = new AiModelRouter(_dbContext, _mockClientFactory.Object, _protectionProvider, _mockLogger.Object);
        var (response, usedProvider, usedModel) = await router.ExecuteWithFallbackAsync(new AiPromptRequest("Sys", "Usr"));

        Assert.False(response.IsSuccess);
        Assert.Equal("AiGloballyDisabled", response.ErrorCode);
        Assert.Equal("System", usedProvider);
        _mockClientFactory.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }
}
