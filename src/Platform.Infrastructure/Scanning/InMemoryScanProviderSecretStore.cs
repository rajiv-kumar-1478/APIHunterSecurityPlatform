using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Development and Unit Test Secret Store implementation ONLY.
/// Must NOT be used in Production deployments.
/// </summary>
public class InMemoryScanProviderSecretStore : IScanProviderSecretStore
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _store = new(StringComparer.OrdinalIgnoreCase);

    public InMemoryScanProviderSecretStore()
    {
        // Seed default development/test secret references
        var bughunterSecrets = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["GROQ_API_KEY"] = "dev-test-reference-groq-key",
            ["VIRUSTOTAL_API_KEY"] = "dev-test-reference-vt-key"
        };
        _store["bughunter"] = bughunterSecrets;
    }

    public Task<ProviderSecretStatus> GetStatusAsync(string providerKey, CancellationToken ct = default)
    {
        var exists = _store.TryGetValue(providerKey, out var keys);

        return Task.FromResult(new ProviderSecretStatus(
            ProviderKey: providerKey,
            Configured: exists && keys!.Count > 0,
            RequiredKeys: new[] { "GROQ_API_KEY" },
            OptionalKeys: new[] { "VIRUSTOTAL_API_KEY", "DEEPSEEK_API_KEY" },
            LastValidatedAtUtc: DateTime.UtcNow
        ));
    }

    public Task<ProviderSecretLease> AcquireLeaseAsync(string providerKey, CancellationToken ct = default)
    {
        _store.TryGetValue(providerKey, out var keys);
        var leaseSecrets = keys != null ? new Dictionary<string, string>(keys) : new Dictionary<string, string>();

        return Task.FromResult(new ProviderSecretLease(providerKey, leaseSecrets, TimeSpan.FromMinutes(10)));
    }
}
