using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class CredentialCandidate
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Keyed pepper HMAC fingerprint: HMAC-SHA256(normalizedSecret, pepperForVersion).
    /// Prevents rainbow table attacks and uniquely identifies credentials across files and repos.
    /// </summary>
    public string SecretFingerprint { get; set; } = string.Empty;

    public int FingerprintKeyVersion { get; set; } = 1;

    public string MaskedValue { get; set; } = string.Empty;
    public string EncryptedRawValue { get; set; } = string.Empty;
    public string CredentialType { get; set; } = string.Empty;

    /// <summary>
    /// Phase 3 candidate statuses: Detected, Triaged, Resolved.
    /// Validation states (Valid, Invalid) are reserved for Phase 4.
    /// </summary>
    public CandidateStatus Status { get; set; } = CandidateStatus.Detected;

    public DateTime FirstDetectedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastDetectedAtUtc { get; set; } = DateTime.UtcNow;
    public int TotalOccurrences { get; set; } = 1;

    public Guid? ResolvedByUserId { get; set; }
    public DateTime? ResolvedAtUtc { get; set; }
    public string? ResolutionNote { get; set; }

    // Navigation
    public User? ResolvedByUser { get; set; }
    public ICollection<CandidateOccurrence> Occurrences { get; set; } = [];
}
