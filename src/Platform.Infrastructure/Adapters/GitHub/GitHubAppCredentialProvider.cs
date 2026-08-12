using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Octokit;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.GitHub;

public class GitHubAppCredentialProvider(
    IOptions<GitHubOptions> options,
    ILogger<GitHubAppCredentialProvider> logger) : IGitHubCredentialProvider
{
    private string? _cachedToken;
    private DateTimeOffset _cachedTokenExpiresAt = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public Task<bool> IsConfiguredAsync(CancellationToken ct = default)
    {
        var opts = options.Value;
        var configured = opts.AppId > 0 &&
                         opts.InstallationId > 0 &&
                         !string.IsNullOrWhiteSpace(opts.PrivateKeyPem);
        return Task.FromResult(configured);
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        if (!await IsConfiguredAsync(ct))
        {
            return null;
        }

        // Return cached token if valid for at least 5 more minutes
        if (_cachedToken != null && _cachedTokenExpiresAt > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            return _cachedToken;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_cachedToken != null && _cachedTokenExpiresAt > DateTimeOffset.UtcNow.AddMinutes(5))
            {
                return _cachedToken;
            }

            var opts = options.Value;
            logger.LogInformation("Refreshing GitHub App installation access token for App ID {AppId}, Installation ID {InstallationId}", opts.AppId, opts.InstallationId);

            var jwtClient = new GitHubClient(new Octokit.ProductHeaderValue(opts.UserAgent))
            {
                Credentials = new Credentials(CreateJwtToken(opts.AppId, opts.PrivateKeyPem), AuthenticationType.Bearer)
            };

            var tokenResponse = await jwtClient.GitHubApps.CreateInstallationToken(opts.InstallationId);
            
            _cachedToken = tokenResponse.Token;
            _cachedTokenExpiresAt = tokenResponse.ExpiresAt;


            logger.LogInformation("GitHub App token refreshed successfully. Expires at: {ExpiresAt}", _cachedTokenExpiresAt);
            return _cachedToken;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to refresh GitHub App installation access token.");
            return null;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static string CreateJwtToken(long appId, string privateKeyPem)
    {
        // Octokit provides GitHubAppJwtAttribute or standard RSA signing
        // Using GitHub's recommended JWT claims
        var payload = new Dictionary<string, object>
        {
            { "iat", DateTimeOffset.UtcNow.AddSeconds(-60).ToUnixTimeSeconds() },
            { "exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds() },
            { "iss", appId.ToString() }
        };

        // For compatibility with Octokit JWT generation:
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(privateKeyPem.ToCharArray());

        var headerJson = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT" });
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payloadBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var unsignedToken = $"{headerBase64}.{payloadBase64}";
        var signatureBytes = rsa.SignData(System.Text.Encoding.UTF8.GetBytes(unsignedToken), System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var signatureBase64 = Convert.ToBase64String(signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return $"{unsignedToken}.{signatureBase64}";
    }
}
