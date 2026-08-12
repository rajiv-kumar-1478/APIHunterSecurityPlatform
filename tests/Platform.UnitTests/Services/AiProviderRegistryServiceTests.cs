using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Auth;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class AiProviderRegistryServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly IDataProtectionProvider _protectionProvider;
    private readonly Mock<IAiModelRouter> _mockRouter;
    private readonly Mock<ICurrentUserContext> _mockUserContext;

    public AiProviderRegistryServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiProviderRegistryTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _protectionProvider = new EphemeralDataProtectionProvider();
        _mockRouter = new Mock<IAiModelRouter>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(Guid.NewGuid());
        _mockUserContext.Setup(u => u.CorrelationId).Returns("test-corr-id");
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task CreateProviderConfig_EncryptsKeyAndMasksPreviewInDto()
    {
        var service = new AiProviderRegistryService(_dbContext, _protectionProvider, _mockRouter.Object, _mockUserContext.Object);
        var createDto = new CreateAiProviderDto("OpenAI", "gpt-4o", 100, true, "sk-proj-secretkey1234");

        var result = await service.CreateProviderConfigAsync(createDto);

        Assert.NotNull(result);
        Assert.Equal("OpenAI", result.ProviderName);
        Assert.Equal("gpt-4o", result.ModelName);
        Assert.True(result.IsKeyConfigured);
        Assert.Equal("****1234", result.KeyPreview);

        // Verify DB row encrypted value is NOT plain text
        var dbRow = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == result.Id);
        Assert.DoesNotContain("sk-proj-secretkey1234", dbRow.EncryptedApiKey);
    }

    [Fact]
    public async Task TestProviderConnection_WithNoKey_ReturnsBlockedNotConfigured()
    {
        var service = new AiProviderRegistryService(_dbContext, _protectionProvider, _mockRouter.Object, _mockUserContext.Object);
        var createDto = new CreateAiProviderDto("DeepSeek", "deepseek-chat", 90, true, null);
        var created = await service.CreateProviderConfigAsync(createDto);

        var testResult = await service.TestProviderConnectionAsync(created.Id);

        Assert.False(testResult.IsSuccess);
        Assert.Equal("BLOCKED / NOT CONFIGURED", testResult.Status);
    }

    [Fact]
    public async Task TestProviderConnection_SuccessfulTest_RestoresHealthToHealthy()
    {
        var service = new AiProviderRegistryService(_dbContext, _protectionProvider, _mockRouter.Object, _mockUserContext.Object);
        var createDto = new CreateAiProviderDto("OpenAI", "gpt-4o", 100, true, "sk-valid-key");
        var created = await service.CreateProviderConfigAsync(createDto);

        // Simulate provider marked Unreachable due to prior key failure
        var dbRow = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == created.Id);
        dbRow.HealthStatus = AiHealthStatus.Unreachable;
        dbRow.LastErrorReason = "Authentication failure";
        await _dbContext.SaveChangesAsync();

        _mockRouter.Setup(r => r.TestProviderConfigAsync(It.IsAny<AiProviderConfig>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AiPromptResponse(
                IsSuccess: true,
                RawResponseContent: "{\"pong\":true}",
                NormalizedJsonContent: "{\"pong\":true}",
                PromptTokens: 10,
                CompletionTokens: 5,
                ProviderName: "OpenAI",
                ModelName: "gpt-4o",
                LatencyMs: 150,
                ErrorCode: null,
                ErrorMessage: null,
                IsRetryable: false));

        var testResult = await service.TestProviderConnectionAsync(created.Id);

        Assert.True(testResult.IsSuccess);
        Assert.Equal("SUCCESS", testResult.Status);

        var restored = await _dbContext.AiProviderConfigs.FirstAsync(p => p.Id == created.Id);
        Assert.Equal(AiHealthStatus.Healthy, restored.HealthStatus);
        Assert.Null(restored.LastErrorReason);
        Assert.Null(restored.CooldownUntilUtc);
    }

    [Fact]
    public async Task GlobalAiState_Toggle_UpdatesSystemSettingAndAuditsEvent()
    {
        var service = new AiProviderRegistryService(_dbContext, _protectionProvider, _mockRouter.Object, _mockUserContext.Object);

        var pausedState = await service.SetGlobalAiStateAsync(false);
        Assert.False(pausedState.IsEnabled);

        var setting = await _dbContext.SystemSettings.FirstOrDefaultAsync(s => s.Key == "ai.global_enabled");
        Assert.NotNull(setting);
        Assert.Equal("false", setting.Value);

        var audit = await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.AiGlobalPause);
        Assert.NotNull(audit);

        var resumedState = await service.SetGlobalAiStateAsync(true);
        Assert.True(resumedState.IsEnabled);
    }
}
