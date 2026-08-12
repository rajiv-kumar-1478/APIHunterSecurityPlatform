namespace Platform.Domain.Contracts;

public interface IGitHubCredentialProvider
{
    Task<string?> GetAccessTokenAsync(CancellationToken ct = default);
    Task<bool> IsConfiguredAsync(CancellationToken ct = default);
}
