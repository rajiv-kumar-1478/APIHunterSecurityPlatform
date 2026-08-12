using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SnapshotFile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SnapshotId { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string? FileExtension { get; set; }
    public string ContentHash { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public bool IsAnalyzed { get; set; }
    public bool IsBinary { get; set; }
    public bool IsSkipped { get; set; }
    public SkipReason? SkipReason { get; set; }

    // Navigation
    public RepositorySnapshot Snapshot { get; set; } = null!;
    public ICollection<CandidateOccurrence> Occurrences { get; set; } = [];
}
