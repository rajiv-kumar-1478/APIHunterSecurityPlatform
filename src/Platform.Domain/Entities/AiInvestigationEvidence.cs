using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class AiInvestigationEvidence
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? InvestigationId { get; set; }
    public Guid SnapshotId { get; set; }
    public Guid? SnapshotFileId { get; set; }
    public Guid? CandidateId { get; set; }
    public string EvidenceType { get; set; } = string.Empty; // e.g. "DatabaseConfig", "ServerCredential", "CloudDeployment"
    public string FilePath { get; set; } = string.Empty;
    public int StartLine { get; set; }
    public int EndLine { get; set; }
    public FindingConfidence Confidence { get; set; } = FindingConfidence.High;
    public DiscoveryType Source { get; set; } = DiscoveryType.AiInvestigator;
    public string EvidenceJson { get; set; } = "{}";
    public string Fingerprint { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public AiInvestigationJob? Investigation { get; set; }

    public RepositorySnapshot Snapshot { get; set; } = null!;
    public SnapshotFile? SnapshotFile { get; set; }
    public CredentialCandidate? Candidate { get; set; }
}
