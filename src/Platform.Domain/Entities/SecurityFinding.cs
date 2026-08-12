using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityFinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public Guid? SnapshotId { get; set; }

    /// <summary>
    /// Deterministic SHA256 fingerprint: SHA256(RepositoryId + FindingType + CoreEntityId).
    /// Guarantees deduplication across repeated snapshot, AI, and validation analysis runs.
    /// </summary>
    public string FindingFingerprint { get; set; } = string.Empty;

    public FindingType FindingType { get; set; }
    public RiskSeverity Severity { get; set; } = RiskSeverity.Low;
    public FindingConfidence Confidence { get; set; } = FindingConfidence.Medium;
    public FindingStatus Status { get; set; } = FindingStatus.Open;

    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Latest calculated risk score (0 - 100). Step 2 Risk Engine will update this value.
    /// </summary>
    public int RiskScore { get; set; }

    /// <summary>
    /// Itemized factor breakdown JSON for score explainability.
    /// </summary>
    public string RiskFactorBreakdownJson { get; set; } = "[]";

    /// <summary>
    /// Optimistic concurrency version token for lifecycle governance state transitions.
    /// </summary>
    public int LifecycleVersion { get; set; } = 1;

    public DateTime FirstObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ResolvedAtUtc { get; set; }
    public Guid? ResolvedByUserId { get; set; }
    public string? ResolutionReason { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public Repository Repository { get; set; } = null!;
    public RepositorySnapshot? Snapshot { get; set; }
    public User? ResolvedByUser { get; set; }
    public ICollection<SecurityFindingEvidence> Evidences { get; set; } = new List<SecurityFindingEvidence>();
    public ICollection<SecurityFindingStatusHistory> StatusHistories { get; set; } = new List<SecurityFindingStatusHistory>();
}
