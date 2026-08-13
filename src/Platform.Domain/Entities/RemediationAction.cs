using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RemediationAction
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FindingId { get; set; }
    public Guid RepositoryId { get; set; }

    public RemediationActionType ActionType { get; set; }
    public RemediationActionStatus Status { get; set; } = RemediationActionStatus.Proposed;

    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Deterministic SHA256 fingerprint: SHA256(FindingId + ActionType + ProviderKey + ProviderResourceReference).
    /// Used for deduplication to prevent duplicate action creation against active findings.
    /// </summary>
    public string ActionFingerprint { get; set; } = string.Empty;

    /// <summary>
    /// EF Core Optimistic Concurrency Token (.IsConcurrencyToken()).
    /// </summary>
    public int Version { get; set; } = 1;

    /// <summary>
    /// Safety flag requiring explicit human approval before execution. Defaults to true.
    /// </summary>
    public bool RequiresApproval { get; set; } = true;

    public Guid? ProposedByUserId { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public Guid? RejectedByUserId { get; set; }
    public DateTime? RejectedAtUtc { get; set; }

    public string? ApprovalReason { get; set; }
    public string? RejectionReason { get; set; }

    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime? ExecutionStartedAtUtc { get; set; }
    public DateTime? ExecutionCompletedAtUtc { get; set; }

    public string? ProviderKey { get; set; }
    public string? ProviderResourceReference { get; set; }

    public int? PreExecutionRiskScore { get; set; }

    public string? VerificationClaimToken { get; set; }
    public DateTime? VerificationClaimedAtUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public SecurityFinding Finding { get; set; } = null!;
    public Repository Repository { get; set; } = null!;
    public User? ProposedByUser { get; set; }
    public User? ApprovedByUser { get; set; }
    public User? RejectedByUser { get; set; }
    public ICollection<RemediationActionHistory> Histories { get; set; } = new List<RemediationActionHistory>();
    public ICollection<RemediationExecution> Executions { get; set; } = new List<RemediationExecution>();
    public RemediationVerification? Verification { get; set; }
}
