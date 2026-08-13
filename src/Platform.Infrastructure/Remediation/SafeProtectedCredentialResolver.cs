using Platform.Application.Providers;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Remediation;

public class SafeProtectedCredentialResolver : IProtectedCredentialResolver
{
    public Task<ProtectedCredential?> ResolveAsync(
        string providerKey,
        string resourceReference,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(providerKey) || string.IsNullOrWhiteSpace(resourceReference))
        {
            return Task.FromResult<ProtectedCredential?>(null);
        }

        var resolved = new ProtectedCredential(
            providerKey.ToLowerInvariant(),
            resourceReference,
            $"resolved_secret_{resourceReference}");

        return Task.FromResult<ProtectedCredential?>(resolved);
    }
}
