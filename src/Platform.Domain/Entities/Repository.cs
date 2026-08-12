using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class Repository
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Provider { get; set; } = "GitHub";
    public long ProviderRepoId { get; set; }
    public string Owner { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsPrivate { get; set; }
    public string DefaultBranch { get; set; } = "main";
    public AcquisitionStatus AcquisitionStatus { get; set; } = AcquisitionStatus.Pending;
    public DateTime? LastAcquiredAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Concurrency token for EF Core optimistic concurrency.
    /// </summary>
    public byte[] RowVersion { get; set; } = [];

    // Navigation
    public ICollection<RepositorySource> Sources { get; set; } = [];
    public ICollection<RepositorySnapshot> Snapshots { get; set; } = [];
    public ICollection<CandidateOccurrence> Occurrences { get; set; } = [];
}
