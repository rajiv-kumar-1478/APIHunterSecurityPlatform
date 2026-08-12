using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Adapters.GitHub;
using Xunit;

namespace Platform.UnitTests;

public class GitHubProviderTests
{
    [Fact]
    public async Task GitHubPatCredentialProvider_ReturnsConfiguredToken()
    {
        var options = Options.Create(new GitHubOptions
        {
            PersonalAccessToken = "ghp_test_token_1234567890"
        });

        var provider = new GitHubPatCredentialProvider(options);

        var isConfigured = await provider.IsConfiguredAsync();
        var token = await provider.GetAccessTokenAsync();

        Assert.True(isConfigured);
        Assert.Equal("ghp_test_token_1234567890", token);
    }

    [Fact]
    public async Task GitHubPatCredentialProvider_Unconfigured_ReturnsNull()
    {
        var options = Options.Create(new GitHubOptions
        {
            PersonalAccessToken = ""
        });

        var provider = new GitHubPatCredentialProvider(options);

        var isConfigured = await provider.IsConfiguredAsync();
        var token = await provider.GetAccessTokenAsync();

        Assert.False(isConfigured);
        Assert.Null(token);
    }

    [Fact]
    public async Task GitHubAppCredentialProvider_Unconfigured_ReturnsNull()
    {
        var options = Options.Create(new GitHubOptions
        {
            AppId = 0,
            InstallationId = 0,
            PrivateKeyPem = ""
        });

        var provider = new GitHubAppCredentialProvider(options, NullLogger<GitHubAppCredentialProvider>.Instance);

        var isConfigured = await provider.IsConfiguredAsync();
        var token = await provider.GetAccessTokenAsync();

        Assert.False(isConfigured);
        Assert.Null(token);
    }
}
