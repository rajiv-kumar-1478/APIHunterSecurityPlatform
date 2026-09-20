using System;
using System.ComponentModel.DataAnnotations;

namespace Platform.Domain.Entities;

/// <summary>
/// Tenant-specific provider settings for integrations that require customer-configured
/// resource endpoints (such as Azure OpenAI).
/// </summary>
public class TenantProviderSetting
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Owning tenant for multi-tenant isolation.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Name of the provider (e.g. "AzureOpenAI").
    /// </summary>
    [MaxLength(100)]
    public string ProviderName { get; set; } = string.Empty;

    /// <summary>
    /// Customer-configured server endpoint URL (e.g. "https://contoso.openai.azure.com").
    /// Must be HTTPS and conform to the provider's allowed domain pattern.
    /// </summary>
    [MaxLength(2048)]
    public string ResourceEndpointUrl { get; set; } = string.Empty;

    /// <summary>
    /// Provider API version query parameter (e.g. "2023-05-15").
    /// </summary>
    [MaxLength(50)]
    public string ApiVersion { get; set; } = "2023-05-15";

    /// <summary>
    /// Whether this provider configuration is enabled.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
