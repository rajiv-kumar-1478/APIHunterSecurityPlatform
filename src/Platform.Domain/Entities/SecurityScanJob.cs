using System;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityScanJob
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? RepositoryId { get; set; }

    public Guid? TargetId { get; set; }

    public string TargetUrl { get; set; } = string.Empty;

    public SecurityScanProfileType ScanProfile { get; set; } = SecurityScanProfileType.Recon;

    public SecurityScanJobStatus Status { get; set; } = SecurityScanJobStatus.Queued;

    public Guid RequestedByUserId { get; set; }

    public string ProviderKey { get; set; } = "bughunter";

    public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime? StartedAtUtc { get; set; }

    public DateTime? CompletedAtUtc { get; set; }

    public DateTime? CancelledAtUtc { get; set; }

    public string? FailureReason { get; set; }

    /// <summary>
    /// EF Core Optimistic Concurrency Token
    /// </summary>
    public int Version { get; set; } = 1;

    // Navigation properties
    public Repository? Repository { get; set; }
    public SecurityTarget? Target { get; set; }
    public User? RequestedByUser { get; set; }
}
