using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.GitHub;

public class GitHubPatCredentialProvider(
    IOptions<GitHubOptions> options) : IGitHubCredentialProvider
{
    public Task<bool> IsConfiguredAsync(CancellationToken ct = default)
    {
        var configured = !string.IsNullOrWhiteSpace(options.Value.PersonalAccessToken);
        return Task.FromResult(configured);
    }

    public Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        var pat = options.Value.PersonalAccessToken;
        return Task.FromResult(string.IsNullOrWhiteSpace(pat) ? null : pat);
    }
}
