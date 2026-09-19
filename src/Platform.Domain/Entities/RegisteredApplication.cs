using System;
using System.ComponentModel.DataAnnotations;

namespace Platform.Domain.Entities;

/// <summary>
/// A registered CI/CD application authorized to submit deployment webhooks.
/// Stores the HMAC signing secret (encrypted via Data Protection), the resolved
/// target URL, and the owning tenant. One row per application identity.
/// </summary>
public class RegisteredApplication
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Stable string identifier used by the CI/CD system (e.g. "app-prod-100").
    /// Unique per tenant.
    /// </summary>
    [MaxLength(256)]
    public string ApplicationId { get; set; } = string.Empty;

    /// <summary>
    /// Owning tenant. Resolved on every webhook request to enforce tenant isolation.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Friendly display name for the application.
    /// </summary>
    [MaxLength(500)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Server-authoritative target URL for scan jobs created via deployment webhook.
    /// Never supplied by the caller.
    /// </summary>
    [MaxLength(2048)]
    public string AuthorizedTargetUrl { get; set; } = string.Empty;

    /// <summary>
    /// Deployment environment tag (e.g. "Production", "Staging").
    /// </summary>
    [MaxLength(100)]
    public string Environment { get; set; } = "Production";

    /// <summary>
    /// Data-Protection-encrypted HMAC-SHA256 signing secret.
    /// Decrypted transiently in memory; never exposed in responses.
    /// </summary>
    public string EncryptedWebhookSecret { get; set; } = string.Empty;

    /// <summary>
    /// When false the application is refused during target resolution.
    /// </summary>
    public bool Enabled { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
