using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class AiProviderConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ProviderName { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string ModelName { get; set; } = string.Empty;
    public int Priority { get; set; } = 100;
    public string EncryptedApiKey { get; set; } = string.Empty;
    public string CapabilitiesJson { get; set; } = "[]";
    public AiHealthStatus HealthStatus { get; set; } = AiHealthStatus.Healthy;
    public DateTime? LastSuccessAtUtc { get; set; }
    public DateTime? LastFailureAtUtc { get; set; }
    public string? LastErrorReason { get; set; }
    public DateTime? RateLimitResetAtUtc { get; set; }
    public DateTime? CooldownUntilUtc { get; set; }
    public int RemainingQuota { get; set; } = 1000;
    public long TotalCallsCount { get; set; } = 0;
    public long FailedCallsCount { get; set; } = 0;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
