namespace Platform.Domain.Contracts;

public record RepositoryMetadata(
    long ProviderRepoId,
    string Owner,
    string Name,
    string FullName,
    string Url,
    string? Description,
    bool IsPrivate,
    string DefaultBranch,
    DateTimeOffset? PushedAtUtc);

public interface IRepositoryProvider
{
    string ProviderName { get; }
    Task<RepositoryMetadata> GetRepositoryMetadataAsync(string owner, string name, CancellationToken ct = default);
    Task<Stream> DownloadArchiveAsync(string owner, string name, string commitRef, CancellationToken ct = default);
    Task<string> GetLatestCommitShaAsync(string owner, string name, string branch, CancellationToken ct = default);
    Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default);
}
