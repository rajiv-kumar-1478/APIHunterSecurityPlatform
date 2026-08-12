namespace Platform.Domain.Entities;

public class ApiHunterRepoReference
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ApiHunterRecordId { get; set; }
    public long SourceReferenceId { get; set; } // RepoReferences.Id from APIHunterV2
    public string RepoUrl { get; set; } = string.Empty;
    public string RepoOwner { get; set; } = string.Empty;
    public string RepoName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileUrl { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public string? CodeContext { get; set; }
    public DateTime FoundUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public ApiHunterRecord ApiHunterRecord { get; set; } = null!;
}
