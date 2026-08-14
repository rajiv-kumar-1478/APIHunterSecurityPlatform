using System;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable record of a security finding observation during a specific scan job execution.
/// Provides auditable evidence for lifecycle state transitions (New -> Persistent -> NotObserved -> Resolved).
/// </summary>
public class ScanFindingObservation
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid FindingId { get; set; }
    public SecurityFinding Finding { get; set; } = null!;

    public Guid ScanJobId { get; set; }
    public SecurityScanJob ScanJob { get; set; } = null!;

    public DateTime ObservedAtUtc { get; set; } = DateTime.UtcNow;

    public bool WasObserved { get; set; }

    public bool FullCoverageConfirmed { get; set; }

    public string ToolCoverageHash { get; set; } = string.Empty;
}
