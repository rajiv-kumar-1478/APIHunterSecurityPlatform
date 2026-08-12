using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RepositorySnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public string CommitSha { get; set; } = string.Empty;
    public string BranchName { get; set; } = "main";
    public string? ArchiveObjectKey { get; set; }
    public long ArchiveSizeBytes { get; set; }
    public int FileCount { get; set; }
    public long TotalSizeBytes { get; set; }
    public DateTime AcquiredAtUtc { get; set; } = DateTime.UtcNow;
    public AnalysisStatus AnalysisStatus { get; set; } = AnalysisStatus.Pending;
    public DateTime? AnalysisCompletedAtUtc { get; set; }
    public int CandidatesFound { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public Repository Repository { get; set; } = null!;
    public ICollection<SnapshotFile> Files { get; set; } = [];
}
