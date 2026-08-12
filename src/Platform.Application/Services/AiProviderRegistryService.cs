using System.Net.Http;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Application.Services;

public class AiProviderRegistryService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IDataProtector _protector;
    private readonly IAiModelRouter _modelRouter;
    private readonly ICurrentUserContext _currentUser;

    public AiProviderRegistryService(
        IPlatformDbContext dbContext,
        IDataProtectionProvider protectionProvider,
        IAiModelRouter modelRouter,
        ICurrentUserContext currentUser)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        if (protectionProvider == null) throw new ArgumentNullException(nameof(protectionProvider));
        _protector = protectionProvider.CreateProtector("Platform.AiProvider.ApiKey");
        _modelRouter = modelRouter ?? throw new ArgumentNullException(nameof(modelRouter));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
    }

    public async Task<List<AiProviderDto>> GetProvidersAsync(CancellationToken ct = default)
    {
        var configs = await _dbContext.AiProviderConfigs
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.ProviderName)
            .ToListAsync(ct);

        return configs.Select(ToDto).ToList();
    }

    public async Task<AiProviderDto> GetProviderByIdAsync(Guid id, CancellationToken ct = default)
    {
        var config = await _dbContext.AiProviderConfigs.FirstOrDefaultAsync(p => p.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI provider config with ID '{id}' was not found.");

        return ToDto(config);
    }

    public async Task<AiProviderDto> CreateProviderConfigAsync(CreateAiProviderDto dto, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(dto.ProviderName)) throw new ArgumentException("ProviderName is required.", nameof(dto));
        if (string.IsNullOrWhiteSpace(dto.ModelName)) throw new ArgumentException("ModelName is required.", nameof(dto));

        string encryptedKey = string.Empty;
        if (!string.IsNullOrWhiteSpace(dto.RawApiKey))
        {
            encryptedKey = _protector.Protect(dto.RawApiKey.Trim());
        }

        var config = new AiProviderConfig
        {
            ProviderName = dto.ProviderName.Trim(),
            ModelName = dto.ModelName.Trim(),
            Priority = dto.Priority,
            IsEnabled = dto.IsEnabled,
            EncryptedApiKey = encryptedKey,
            CapabilitiesJson = JsonSerializer.Serialize(dto.Capabilities ?? new List<string> { "JsonOutput" }),
            HealthStatus = AiHealthStatus.Healthy,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };

        _dbContext.AiProviderConfigs.Add(config);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiProviderConfigured,
            UserId = _currentUser.UserId,
            ResourceType = "AiProviderConfig",
            ResourceId = config.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { config.ProviderName, config.ModelName, config.Priority }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return ToDto(config);
    }

    public async Task<AiProviderDto> UpdateProviderConfigAsync(Guid id, UpdateAiProviderDto dto, CancellationToken ct = default)
    {
        var config = await _dbContext.AiProviderConfigs.FirstOrDefaultAsync(p => p.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI provider config with ID '{id}' was not found.");

        if (!string.IsNullOrWhiteSpace(dto.ModelName)) config.ModelName = dto.ModelName.Trim();
        if (dto.Priority.HasValue) config.Priority = dto.Priority.Value;
        if (dto.IsEnabled.HasValue) config.IsEnabled = dto.IsEnabled.Value;
        if (dto.Capabilities != null) config.CapabilitiesJson = JsonSerializer.Serialize(dto.Capabilities);

        if (!string.IsNullOrWhiteSpace(dto.RawApiKey))
        {
            config.EncryptedApiKey = _protector.Protect(dto.RawApiKey.Trim());
        }

        config.UpdatedAtUtc = DateTime.UtcNow;

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiProviderConfigured,
            UserId = _currentUser.UserId,
            ResourceType = "AiProviderConfig",
            ResourceId = config.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { config.ProviderName, config.ModelName, config.Priority, config.IsEnabled }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return ToDto(config);
    }

    public async Task<AiProviderDto> ToggleProviderAsync(Guid id, bool isEnabled, CancellationToken ct = default)
    {
        var config = await _dbContext.AiProviderConfigs.FirstOrDefaultAsync(p => p.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI provider config with ID '{id}' was not found.");

        config.IsEnabled = isEnabled;
        config.UpdatedAtUtc = DateTime.UtcNow;

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiProviderToggled,
            UserId = _currentUser.UserId,
            ResourceType = "AiProviderConfig",
            ResourceId = config.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { config.ProviderName, isEnabled }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return ToDto(config);
    }

    public async Task<AiProviderDto> ResetProviderCooldownAsync(Guid id, CancellationToken ct = default)
    {
        var config = await _dbContext.AiProviderConfigs.FirstOrDefaultAsync(p => p.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI provider config with ID '{id}' was not found.");

        config.RateLimitResetAtUtc = null;
        config.CooldownUntilUtc = null;
        config.FailedCallsCount = 0;
        config.HealthStatus = AiHealthStatus.Healthy;
        config.LastErrorReason = null;
        config.UpdatedAtUtc = DateTime.UtcNow;

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiProviderCooldownReset,
            UserId = _currentUser.UserId,
            ResourceType = "AiProviderConfig",
            ResourceId = config.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { config.ProviderName, reset = true }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return ToDto(config);
    }

    public async Task<AiTestResultDto> TestProviderConnectionAsync(Guid id, CancellationToken ct = default)
    {
        var config = await _dbContext.AiProviderConfigs.FirstOrDefaultAsync(p => p.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI provider config with ID '{id}' was not found.");

        if (string.IsNullOrWhiteSpace(config.EncryptedApiKey))
        {
            return new AiTestResultDto(
                Status: "BLOCKED / NOT CONFIGURED",
                Message: "API key is not configured for this provider.",
                IsSuccess: false,
                TestedAtUtc: DateTime.UtcNow);
        }

        if (!config.IsEnabled)
        {
            return new AiTestResultDto(
                Status: "BLOCKED / DISABLED",
                Message: "Provider is currently disabled.",
                IsSuccess: false,
                TestedAtUtc: DateTime.UtcNow);
        }

        var response = await _modelRouter.TestProviderConfigAsync(config, ct);

        if (response.IsSuccess)
        {
            config.LastSuccessAtUtc = DateTime.UtcNow;
            config.LastErrorReason = null;
            config.HealthStatus = AiHealthStatus.Healthy;
            config.RateLimitResetAtUtc = null;
            config.CooldownUntilUtc = null;
            config.FailedCallsCount = 0;
        }
        else
        {
            config.LastFailureAtUtc = DateTime.UtcNow;
            config.LastErrorReason = response.ErrorMessage;
            config.HealthStatus = response.ErrorCode == "RateLimited" ? AiHealthStatus.RateLimited : (response.IsRetryable ? AiHealthStatus.Degraded : AiHealthStatus.Unreachable);
        }

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiProviderTested,
            UserId = _currentUser.UserId,
            ResourceType = "AiProviderConfig",
            ResourceId = config.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { config.ProviderName, testSuccess = response.IsSuccess }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);

        return new AiTestResultDto(
            Status: response.IsSuccess ? "SUCCESS" : $"FAILED ({response.ErrorCode})",
            Message: response.IsSuccess ? "Provider connection and response verified successfully." : (response.ErrorMessage ?? "Test failed."),
            IsSuccess: response.IsSuccess,
            TestedAtUtc: DateTime.UtcNow);
    }

    public async Task<GlobalAiStateDto> GetGlobalAiStateAsync(CancellationToken ct = default)
    {
        var setting = await _dbContext.SystemSettings
            .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", ct);

        bool isEnabled = setting == null || !string.Equals(setting.Value, "false", StringComparison.OrdinalIgnoreCase);
        return new GlobalAiStateDto(isEnabled, isEnabled ? "AI analysis is active." : "AI analysis is paused globally by Admin. Queued jobs are preserved.");
    }

    public async Task<GlobalAiStateDto> SetGlobalAiStateAsync(bool isEnabled, CancellationToken ct = default)
    {
        var setting = await _dbContext.SystemSettings
            .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", ct);

        if (setting == null)
        {
            setting = new SystemSetting
            {
                Key = "ai.global_enabled",
                Value = isEnabled ? "true" : "false",
                ValueType = SettingValueType.Boolean,
                Description = "Admin global toggle to enable or pause AI repository analysis execution."
            };
            _dbContext.SystemSettings.Add(setting);
        }
        else
        {
            setting.Value = isEnabled ? "true" : "false";
            setting.UpdatedAtUtc = DateTime.UtcNow;
        }

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = isEnabled ? AuditEventCode.AiGlobalResume : AuditEventCode.AiGlobalPause,
            UserId = _currentUser.UserId,
            ResourceType = "SystemSetting",
            ResourceId = "ai.global_enabled",
            Metadata = JsonSerializer.Serialize(new { isEnabled }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return new GlobalAiStateDto(isEnabled, isEnabled ? "AI analysis is active." : "AI analysis is paused globally by Admin. Queued jobs are preserved.");
    }

    private AiProviderDto ToDto(AiProviderConfig config)
    {
        bool isConfigured = !string.IsNullOrWhiteSpace(config.EncryptedApiKey);
        string keyPreview = string.Empty;

        if (isConfigured)
        {
            try
            {
                var rawKey = _protector.Unprotect(config.EncryptedApiKey);
                keyPreview = rawKey.Length > 4 ? "****" + rawKey[^4..] : "****";
            }
            catch
            {
                keyPreview = "****";
            }
        }

        List<string> caps;
        try
        {
            caps = JsonSerializer.Deserialize<List<string>>(config.CapabilitiesJson) ?? new List<string>();
        }
        catch
        {
            caps = new List<string>();
        }

        return new AiProviderDto(
            config.Id,
            config.ProviderName,
            config.ModelName,
            config.Priority,
            config.IsEnabled,
            isConfigured,
            keyPreview,
            caps,
            config.HealthStatus.ToString(),
            config.LastSuccessAtUtc,
            config.LastFailureAtUtc,
            config.LastErrorReason,
            config.RateLimitResetAtUtc,
            config.CooldownUntilUtc,
            config.RemainingQuota,
            config.TotalCallsCount,
            config.FailedCallsCount,
            config.CreatedAtUtc,
            config.UpdatedAtUtc);
    }
}

public record CreateAiProviderDto(
    string ProviderName,
    string ModelName,
    int Priority = 100,
    bool IsEnabled = true,
    string? RawApiKey = null,
    List<string>? Capabilities = null);

public record UpdateAiProviderDto(
    string? ModelName = null,
    int? Priority = null,
    bool? IsEnabled = null,
    string? RawApiKey = null,
    List<string>? Capabilities = null);

public record AiProviderDto(
    Guid Id,
    string ProviderName,
    string ModelName,
    int Priority,
    bool IsEnabled,
    bool IsKeyConfigured,
    string KeyPreview,
    List<string> Capabilities,
    string HealthStatus,
    DateTime? LastSuccessAtUtc,
    DateTime? LastFailureAtUtc,
    string? LastErrorReason,
    DateTime? RateLimitResetAtUtc,
    DateTime? CooldownUntilUtc,
    int RemainingQuota,
    long TotalCallsCount,
    long FailedCallsCount,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record AiTestResultDto(
    string Status,
    string Message,
    bool IsSuccess,
    DateTime TestedAtUtc);

public record GlobalAiStateDto(
    bool IsEnabled,
    string StatusMessage);
