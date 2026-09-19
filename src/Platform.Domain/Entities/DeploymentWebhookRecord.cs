using System;
using System.ComponentModel.DataAnnotations;

namespace Platform.Domain.Entities;

/// <summary>
/// Durable idempotency record for a processed deployment webhook.
/// Written atomically AFTER a scan job is durably created.
/// A retry that finds this record returns DUPLICATE_EVENT_ID without creating
/// a second job.
/// </summary>
public class DeploymentWebhookRecord
{
    /// <summary>
    /// Primary key — uses the webhook ID supplied by the sender as PK so the
    /// unique constraint doubles as the idempotency gate.
    /// </summary>
    [MaxLength(256)]
    public string WebhookId { get; set; } = string.Empty;

    /// <summary>
    /// Application that submitted this webhook.
    /// </summary>
    [MaxLength(256)]
    public string ApplicationId { get; set; } = string.Empty;

    /// <summary>
    /// Scan job that was created for this delivery.
    /// </summary>
    public Guid ScanJobId { get; set; }

    /// <summary>
    /// UTC instant at which the webhook was first accepted and the job created.
    /// </summary>
    public DateTime ProcessedAtUtc { get; set; } = DateTime.UtcNow;
}
