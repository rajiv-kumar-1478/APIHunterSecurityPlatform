using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RepositorySource
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public DiscoveryType DiscoveryType { get; set; } = DiscoveryType.ApiHunterSync;
    public Guid? ApiHunterRecordId { get; set; }
    
    /// <summary>
    /// SourceReferenceId (long) from APIHunterV2.
    /// Note: Type MUST match APIHunterV2 RepoReference.Id / ApiHunterRepoReference.SourceReferenceId (long / BIGINT).
    /// </summary>
    public long? ApiHunterRepoRefId { get; set; }
    
    public string? DiscoveredViaQuery { get; set; }
    public DateTime FirstSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public Repository Repository { get; set; } = null!;
    public ApiHunterRecord? ApiHunterRecord { get; set; }
}
