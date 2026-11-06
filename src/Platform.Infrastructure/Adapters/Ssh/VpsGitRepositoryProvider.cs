using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.Ssh;

/// <summary>
/// Downloads GitHub repositories by running <c>git clone</c> on the VPS over SSH, then streaming the
/// resulting archive back through SFTP. This keeps GitHub traffic and temporary repository data off
/// the application host and avoids the GitHub REST rate limit.
/// </summary>
public sealed partial class VpsGitRepositoryProvider : IRepositoryProvider
{
    private readonly IVpsSshConnectionFactory _ssh;
    private readonly VpsSshOptions _options;
    private readonly GitHubOptions _gitHubOptions;
    private readonly IEnumerable<IGitHubCredentialProvider> _credentialProviders;
    private readonly ILogger<VpsGitRepositoryProvider> _logger;

    public VpsGitRepositoryProvider(
        IVpsSshConnectionFactory ssh,
        IOptions<VpsSshOptions> options,
        IOptions<GitHubOptions> gitHubOptions,
        IEnumerable<IGitHubCredentialProvider> credentialProviders,
        ILogger<VpsGitRepositoryProvider> logger)
    {
        _ssh = ssh;
        _options = options.Value;
        _gitHubOptions = gitHubOptions.Value;
        _credentialProviders = credentialProviders;
        _logger = logger;
    }

    public string ProviderName => "GitHub";

    public async Task<RepositoryMetadata> GetRepositoryMetadataAsync(string owner, string name, CancellationToken ct = default)
    {
        ValidateRepoSegment(owner, nameof(owner));
        ValidateRepoSegment(name, nameof(name));

        var url = BuildRepoUrl(owner, name);
        var token = await GetActiveTokenAsync(ct).ConfigureAwait(false);
        var result = await _ssh.ExecuteAsync(
            $"set -euo pipefail\n{await BuildGitEnvironmentAsync(token, ct).ConfigureAwait(false)}{ShellQuote(_options.GitBinaryPath)} ls-remote --symref {ShellQuote(url)} HEAD",
            ct).ConfigureAwait(false);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to read repository {owner}/{name} on the VPS: {FirstLine(result.StandardError)}");

        var defaultBranch = "main";
        string? headSha = null;

        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.StartsWith("ref: refs/heads/", StringComparison.Ordinal))
            {
                var tab = line.IndexOf('\t');
                var branchRef = (tab > 0 ? line[5..tab] : line[5..]).Trim();
                if (branchRef.StartsWith("refs/heads/", StringComparison.Ordinal))
                    branchRef = branchRef["refs/heads/".Length..];
                if (!string.IsNullOrWhiteSpace(branchRef))
                    defaultBranch = branchRef;
            }
            else
            {
                var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[1] == "HEAD" && IsSha(parts[0]))
                    headSha = parts[0];
            }
        }

        if (string.IsNullOrWhiteSpace(headSha))
            throw new InvalidOperationException($"Repository {owner}/{name} has no readable HEAD (it may be empty or private).");

        return new RepositoryMetadata(
            StableProviderRepoId(owner, name),
            owner,
            name,
            $"{owner}/{name}",
            $"https://github.com/{owner}/{name}",
            null,
            false,
            defaultBranch,
            null);
    }

    public async Task<string> GetLatestCommitShaAsync(string owner, string name, string branch, CancellationToken ct = default)
    {
        ValidateRepoSegment(owner, nameof(owner));
        ValidateRepoSegment(name, nameof(name));
        ValidateRef(branch, nameof(branch));

        var url = BuildRepoUrl(owner, name);
        var token = await GetActiveTokenAsync(ct).ConfigureAwait(false);
        var result = await _ssh.ExecuteAsync(
            $"set -euo pipefail\n{await BuildGitEnvironmentAsync(token, ct).ConfigureAwait(false)}{ShellQuote(_options.GitBinaryPath)} ls-remote {ShellQuote(url)} {ShellQuote($"refs/heads/{branch}")}",
            ct).ConfigureAwait(false);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to resolve branch {branch} for {owner}/{name}: {FirstLine(result.StandardError)}");

        var first = result.StandardOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimEnd('\r'))
            .FirstOrDefault();

        if (string.IsNullOrWhiteSpace(first))
            throw new InvalidOperationException($"Branch '{branch}' was not found in {owner}/{name}.");

        var sha = first.Split('\t', StringSplitOptions.RemoveEmptyEntries)[0];
        if (!IsSha(sha))
            throw new InvalidOperationException($"VPS returned an invalid commit SHA for {owner}/{name}: {sha}");

        return sha;
    }

    public async Task<Stream> DownloadArchiveAsync(string owner, string name, string commitRef, CancellationToken ct = default)
    {
        ValidateRepoSegment(owner, nameof(owner));
        ValidateRepoSegment(name, nameof(name));
        ValidateCommitRef(commitRef);

        var url = BuildRepoUrl(owner, name);
        var token = await GetActiveTokenAsync(ct).ConfigureAwait(false);
        var env = await BuildGitEnvironmentAsync(token, ct).ConfigureAwait(false);

        var workDir = string.IsNullOrWhiteSpace(_options.RemoteWorkDir) ? "/tmp/apihunter-repos" : _options.RemoteWorkDir.TrimEnd('/');
        var remoteDir = $"{workDir}/{Guid.NewGuid():N}";
        var archivePath = $"{remoteDir}/archive.tar.gz";

        var git = ShellQuote(_options.GitBinaryPath);
        var script = $"""
            set -euo pipefail
            umask 077
            d={ShellQuote(remoteDir)}
            rm -rf "$d"
            mkdir -p "$d"
            {git} init --quiet "$d/repo"
            {git} -C "$d/repo" remote add origin {ShellQuote(url)}
            {env}if ! {git} -C "$d/repo" fetch --quiet --no-tags --depth 1 origin {ShellQuote(commitRef)}; then
              {env}{git} -C "$d/repo" fetch --quiet --no-tags origin {ShellQuote(commitRef)}
            fi
            {git} -C "$d/repo" archive --format=tar.gz --output="$d/archive.tar.gz" FETCH_HEAD
            printf '%s\n' "$d/archive.tar.gz"
            """;

        try
        {
            var result = await _ssh.ExecuteAsync(script, ct).ConfigureAwait(false);
            if (result.ExitCode != 0)
                throw new InvalidOperationException($"git clone/archive failed for {owner}/{name}@{commitRef}: {FirstLine(result.StandardError)}");

            _logger.LogInformation("Cloned {Owner}/{Name}@{Commit} on VPS; downloading archive.", owner, name, commitRef);
            return await _ssh.DownloadFileAsync(archivePath, ct).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                await _ssh.ExecuteAsync($"rm -rf {ShellQuote(remoteDir)}", CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clean up remote repository directory {RemoteDir}.", remoteDir);
            }
        }
    }

    public async Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var health = await _ssh.HealthCheckAsync(ct).ConfigureAwait(false);
            sw.Stop();
            return new ComponentHealthResult("VpsGitProvider", health.IsHealthy, health.Status, health.Detail, sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            _logger.LogError(ex, "VPS git provider health check failed.");
            return new ComponentHealthResult("VpsGitProvider", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }

    private async Task<string> GetActiveTokenAsync(CancellationToken ct)
    {
        foreach (var provider in _credentialProviders)
        {
            try
            {
                if (await provider.IsConfiguredAsync(ct).ConfigureAwait(false))
                {
                    var token = await provider.GetAccessTokenAsync(ct).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(token))
                        return token;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "GitHub credential provider failed; trying the next provider.");
            }
        }

        return _gitHubOptions.PersonalAccessToken ?? string.Empty;
    }

    private Task<string> BuildGitEnvironmentAsync(string token, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token))
            return Task.FromResult("export GIT_TERMINAL_PROMPT=0\n");

        var header = $"AUTHORIZATION: bearer {token}";
        return Task.FromResult(
            "export GIT_TERMINAL_PROMPT=0\n" +
            "export GIT_CONFIG_COUNT=1\n" +
            "export GIT_CONFIG_KEY_0=http.extraheader\n" +
            $"export GIT_CONFIG_VALUE_0={ShellQuote(header)}\n");
    }

    private static string BuildRepoUrl(string owner, string name) => $"https://github.com/{owner}/{name}.git";

    private static string FirstLine(string value)
    {
        var line = value.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(line) ? "unknown error" : line.Trim();
    }

    private static string ShellQuote(string value) => VpsSshConnectionFactory.ShellQuote(value);

    private static bool IsSha(string value) => ShaRegex().IsMatch(value);

    private static long StableProviderRepoId(string owner, string name)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{owner}/{name}".ToLowerInvariant()));
        return BitConverter.ToInt64(hash, 0) & long.MaxValue;
    }

    private static void ValidateRepoSegment(string value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 100)
            throw new ArgumentException("Repository owner/name is empty or too long.", paramName);
        if (value is "." or ".." || value.StartsWith('-') || value.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("Repository owner/name contains an unsafe value.", paramName);
        if (!RepoSegmentRegex().IsMatch(value))
            throw new ArgumentException("Repository owner/name contains invalid characters.", paramName);
    }

    private static void ValidateRef(string value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255)
            throw new ArgumentException("Git ref is empty or too long.", paramName);
        if (value.StartsWith('-') || value.Contains("..", StringComparison.Ordinal) ||
            value.Contains("//", StringComparison.Ordinal) || value.StartsWith('/') || value.EndsWith('/') ||
            value.Contains('\\') || value.Contains(':') || value.Contains('~') || value.Contains('^') ||
            value.Contains('?') || value.Contains('*') || value.Contains('[') || value.Any(char.IsWhiteSpace))
            throw new ArgumentException("Git ref contains unsafe characters.", paramName);
        if (!RefRegex().IsMatch(value))
            throw new ArgumentException("Git ref contains invalid characters.", paramName);
    }

    private static void ValidateCommitRef(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255)
            throw new ArgumentException("Commit ref is empty or too long.", nameof(value));
        if (value == "HEAD")
            return;
        if (IsSha(value))
            return;
        ValidateRef(value, nameof(value));
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")]
    private static partial Regex RepoSegmentRegex();

    [GeneratedRegex("^[A-Za-z0-9._/-]{1,255}$")]
    private static partial Regex RefRegex();

    [GeneratedRegex("^[A-Fa-f0-9]{7,40}$")]
    private static partial Regex ShaRegex();
}
