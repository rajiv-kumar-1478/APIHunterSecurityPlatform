namespace Platform.Domain.Entities;

public class CandidateOccurrence
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CandidateId { get; set; }
    public Guid SnapshotFileId { get; set; }
    public Guid RepositoryId { get; set; }

    public string DetectionRuleId { get; set; } = string.Empty;
    public int RuleVersion { get; set; } = 1;

    /// <summary>
    /// Occurrence fingerprint: SHA256(CandidateId + SnapshotFileId + RuleId + RuleVersion + LineNumber + MatchStartIndex + MatchLength).
    /// Guarantees deterministic occurrence identity even if multiple instances appear on the same line.
    /// </summary>
    public string OccurrenceFingerprint { get; set; } = string.Empty;

    public int LineNumber { get; set; }
    public int MatchStartIndex { get; set; }
    public int MatchLength { get; set; }

    /// <summary>
    /// Redacted line content stored permanently.
    /// </summary>
    public string? LineContentRedacted { get; set; }

    /// <summary>
    /// Optional short-term encrypted raw context line (subject to admin retention/purge policy).
    /// </summary>
    public string? LineContentRawEncrypted { get; set; }

    public string Confidence { get; set; } = "High";
    public DateTime DetectedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public CredentialCandidate Candidate { get; set; } = null!;
    public SnapshotFile SnapshotFile { get; set; } = null!;
    public Repository Repository { get; set; } = null!;
    public DetectionRule DetectionRule { get; set; } = null!;
}
