using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Production Secret Store implementation resolving protected secret references via ASP.NET Core DataProtection.
/// </summary>
public class ConfigurationScanProviderSecretStore : IScanProviderSecretStore
{
    private readonly IConfiguration _configuration;
    private readonly IDataProtector _protector;
    private readonly ILogger<ConfigurationScanProviderSecretStore> _logger;

    public ConfigurationScanProviderSecretStore(
        IConfiguration configuration,
        IDataProtectionProvider dataProtectionProvider,
        ILogger<ConfigurationScanProviderSecretStore> logger)
    {
        _configuration = configuration;
        _protector = dataProtectionProvider.CreateProtector("Platform.Scanning.ProviderSecrets");
        _logger = logger;
    }

    public Task<ProviderSecretStatus> GetStatusAsync(string providerKey, CancellationToken ct = default)
    {
        var section = _configuration.GetSection($"Scanning:Providers:{providerKey}:Secrets");
        var configured = section.Exists();

        return Task.FromResult(new ProviderSecretStatus(
            ProviderKey: providerKey,
            Configured: configured,
            RequiredKeys: new[] { "GROQ_API_KEY" },
            OptionalKeys: new[] { "VIRUSTOTAL_API_KEY", "DEEPSEEK_API_KEY" },
            LastValidatedAtUtc: DateTime.UtcNow
        ));
    }

    public Task<ProviderSecretLease> AcquireLeaseAsync(string providerKey, CancellationToken ct = default)
    {
        var section = _configuration.GetSection($"Scanning:Providers:{providerKey}:Secrets");
        var leaseSecrets = new Dictionary<string, string>();

        if (section.Exists())
        {
            foreach (var child in section.GetChildren())
            {
                if (!string.IsNullOrEmpty(child.Value))
                {
                    try
                    {
                        // Decrypt protected secret reference if encrypted, else fallback to configured key
                        var decrypted = child.Value.StartsWith("CfDJ8") ? _protector.Unprotect(child.Value) : child.Value;
                        leaseSecrets[child.Key] = decrypted;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to unprotect secret '{SecretKey}' for provider '{ProviderKey}'.", child.Key, providerKey);
                    }
                }
            }
        }

        _logger.LogDebug("Acquired secret lease for provider '{ProviderKey}' containing {Count} keys.", providerKey, leaseSecrets.Count);
        return Task.FromResult(new ProviderSecretLease(providerKey, leaseSecrets, TimeSpan.FromMinutes(15)));
    }
}
