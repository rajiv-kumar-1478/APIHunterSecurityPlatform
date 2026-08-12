using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class ApiHunterRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public long SourceRecordId { get; set; } // APIKeys.Id from APIHunterV2
    public string MaskedKey { get; set; } = string.Empty;
    public string RawKeyEncrypted { get; set; } = string.Empty;
    public PlatformKeyStatus Status { get; set; } = PlatformKeyStatus.Unverified;
    public string ApiType { get; set; } = string.Empty;
    public string SearchProvider { get; set; } = string.Empty;
    public DateTime FirstFoundUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastFoundUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastCheckedUtc { get; set; }
    public string? ValidationResponse { get; set; }
    public string? Balance { get; set; }
    public string? AccountTier { get; set; }
    public string? AwsAccountId { get; set; }
    public string? AwsRiskLevel { get; set; }
    public DateTime ImportedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<ApiHunterRepoReference> RepoReferences { get; set; } = [];
}
