using System.Diagnostics;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Octokit;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.GitHub;

public class GitHubRepositoryProvider(
    IEnumerable<IGitHubCredentialProvider> credentialProviders,
    IHttpClientFactory httpClientFactory,
    IOptions<GitHubOptions> options,
    ILogger<GitHubRepositoryProvider> logger) : IRepositoryProvider
{
    public string ProviderName => "GitHub";

    public async Task<RepositoryMetadata> GetRepositoryMetadataAsync(string owner, string name, CancellationToken ct = default)
    {
        var client = await CreateClientAsync(ct);
        var repo = await client.Repository.Get(owner, name);

        return new RepositoryMetadata(
            repo.Id,
            repo.Owner.Login,
            repo.Name,
            repo.FullName,
            repo.HtmlUrl,
            repo.Description,
            repo.Private,
            repo.DefaultBranch ?? "main",
            repo.PushedAt);
    }

    public async Task<string> GetLatestCommitShaAsync(string owner, string name, string branch, CancellationToken ct = default)
    {
        var client = await CreateClientAsync(ct);
        var branchInfo = await client.Repository.Branch.Get(owner, name, branch);
        return branchInfo.Commit.Sha;
    }

    public async Task<Stream> DownloadArchiveAsync(string owner, string name, string commitRef, CancellationToken ct = default)
    {
        // Octokit tarball archive download endpoint
        var token = await GetActiveTokenAsync(ct);
        var archiveUrl = $"https://api.github.com/repos/{owner}/{name}/tarball/{commitRef}";

        var httpClient = httpClientFactory.CreateClient("GitHubArchive");
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(options.Value.UserAgent);

        if (!string.IsNullOrWhiteSpace(token))
        {
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var response = await httpClient.GetAsync(archiveUrl, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStreamAsync(ct);
    }

    public async Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var client = await CreateClientAsync(ct);
            var rateLimits = await client.RateLimit.GetRateLimits();
            sw.Stop();

            var coreLimit = rateLimits.Resources.Core;
            var detail = $"Remaining Quota: {coreLimit.Remaining}/{coreLimit.Limit}, Resets at: {coreLimit.Reset.ToUniversalTime():HH:mm:ss} UTC";

            // Low rate limit is reported as a metric, not an automatic service failure
            return new ComponentHealthResult("GitHubProvider", true, "Healthy", detail, sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogError(ex, "GitHub health check probe failed.");
            return new ComponentHealthResult("GitHubProvider", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }

    private async Task<GitHubClient> CreateClientAsync(CancellationToken ct)
    {
        var client = new GitHubClient(new Octokit.ProductHeaderValue(options.Value.UserAgent));
        var token = await GetActiveTokenAsync(ct);


        if (!string.IsNullOrWhiteSpace(token))
        {
            client.Credentials = new Credentials(token, AuthenticationType.Bearer);
        }

        return client;
    }

    private async Task<string?> GetActiveTokenAsync(CancellationToken ct)
    {
        foreach (var provider in credentialProviders)
        {
            if (await provider.IsConfiguredAsync(ct))
            {
                var token = await provider.GetAccessTokenAsync(ct);
                if (!string.IsNullOrWhiteSpace(token))
                {
                    return token;
                }
            }
        }
        return null;
    }
}
