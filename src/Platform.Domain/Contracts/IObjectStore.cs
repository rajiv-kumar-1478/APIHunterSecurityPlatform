namespace Platform.Domain.Contracts;

public record ObjectStoreItemMetadata(string Key, long SizeBytes, DateTime LastModifiedUtc, string? ContentType);

public interface IObjectStore
{
    Task<string> PutAsync(string key, Stream content, string? contentType = null, CancellationToken ct = default);
    Task<Stream> GetAsync(string key, CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default);
}
