using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityFindingEvidence
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FindingId { get; set; }

    public FindingEvidenceType EvidenceType { get; set; }
    public DiscoveryType DiscoverySource { get; set; } = DiscoveryType.DeterministicDetector;

    /// <summary>
    /// SHA256 evidence fingerprint: SHA256(FindingId + EvidenceType + SourceEntityId).
    /// Guarantees evidence idempotency across repeated ingestion runs.
    /// </summary>
    public string EvidenceFingerprint { get; set; } = string.Empty;

    public Guid? SnapshotId { get; set; }
    public Guid? SnapshotFileId { get; set; }
    public Guid? CandidateId { get; set; }
    public Guid? ValidationResultId { get; set; }
    public Guid? IntelligenceNodeId { get; set; }
    public Guid? IntelligenceEdgeId { get; set; }

    public string EvidenceReference { get; set; } = string.Empty;

    /// <summary>
    /// Sanitized JSON payload with zero raw credentials.
    /// </summary>
    public string SafeEvidenceJson { get; set; } = "{}";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public SecurityFinding Finding { get; set; } = null!;
}
