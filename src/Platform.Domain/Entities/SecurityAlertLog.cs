using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Audit & Deduplication record for dispatched and in-flight security alerts (Phase 6 Step 7).
/// Used by SecurityAlertService to perform atomic deduplication and enforce cooldown windows.
/// </summary>
public class SecurityAlertLog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? FindingId { get; set; }
    public Guid? RepositoryId { get; set; }
    public Guid? CandidateId { get; set; }

    /// <summary>
    /// Finding fingerprint or canonical resource identifier.
    /// </summary>
    public string FindingFingerprint { get; set; } = string.Empty;

    /// <summary>
    /// Reason code (e.g. "CredentialRevoked", "CriticalFindingDetected", "RiskScoreEscalated").
    /// </summary>
    public string AlertReason { get; set; } = string.Empty;

    /// <summary>
    /// Deterministic deduplication fingerprint:
    /// Finding alert: SHA256("finding:" + FindingFingerprint + ":" + AlertReason + ":" + Recipient)
    /// Repository alert: SHA256("repository:" + RepositoryId + ":" + AlertReason + ":" + Recipient)
    /// </summary>
    public string AlertFingerprint { get; set; } = string.Empty;

    public RiskSeverity Severity { get; set; } = RiskSeverity.High;
    public int RiskScore { get; set; }
    public string Recipient { get; set; } = string.Empty;

    public DateTime SentAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Atomic claim token for concurrency protection during alert dispatch.
    /// </summary>
    public Guid? ClaimToken { get; set; }

    /// <summary>
    /// Timestamp when atomic claim was established.
    /// </summary>
    public DateTime? ClaimedAtUtc { get; set; }
}
