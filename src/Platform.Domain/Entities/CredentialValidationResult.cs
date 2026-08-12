using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class CredentialValidationResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CandidateId { get; set; }
    public string ProviderName { get; set; } = string.Empty;
    public ValidationStatus Status { get; set; } = ValidationStatus.Pending;
    public ValidationConfidence Confidence { get; set; } = ValidationConfidence.Indeterminate;
    public string ValidatorVersion { get; set; } = "1.0.0";
    public string PolicyVersion { get; set; } = "1.0.0";
    public string ResponseClassification { get; set; } = string.Empty;
    public string SafeEvidenceJson { get; set; } = "{}";
    public long LatencyMs { get; set; }
    public int? HttpStatusCode { get; set; }
    public DateTime? RetryAfterUtc { get; set; }
    public int ValidationAttemptNumber { get; set; } = 1;
    public Guid? AnalysisJobId { get; set; }
    public DateTime ValidatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // ─── Phase 6 Step 6 — Continuous Revalidation Processing ─────────────────

    /// <summary>
    /// Null = unprocessed. Non-null = timestamp when consequence processing completed.
    /// This is the idempotency gate — processed results are never reprocessed.
    /// </summary>
    public DateTime? ProcessedForFindingAtUtc { get; set; }

    /// <summary>
    /// Atomic ownership claim token. Set before processing begins; cleared on completion.
    /// Null = unclaimed and ready. Prevents two worker instances from processing the same result.
    /// </summary>
    public Guid? ProcessingClaimToken { get; set; }

    /// <summary>
    /// When the processing claim was set. Used to detect and expire stale claims
    /// (e.g., worker crashed mid-processing). Stale threshold: 5 minutes.
    /// </summary>
    public DateTime? ProcessingClaimedAtUtc { get; set; }

    // Navigation
    public CredentialCandidate Candidate { get; set; } = null!;
    public AnalysisJob? AnalysisJob { get; set; }
}

