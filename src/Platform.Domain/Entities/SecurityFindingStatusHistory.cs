using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable, append-only record tracking every status transition of a SecurityFinding.
/// Provides an auditable lifecycle history for governance and compliance.
/// </summary>
public class SecurityFindingStatusHistory
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FindingId { get; set; }
    public FindingStatus FromStatus { get; set; }
    public FindingStatus ToStatus { get; set; }
    public Guid? ChangedByUserId { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string MetadataJson { get; set; } = "{}";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public SecurityFinding Finding { get; set; } = null!;
    public User? ChangedByUser { get; set; }
}
