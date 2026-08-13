using Platform.Domain.Contracts;

namespace Platform.Application.Providers;

public interface IProtectedCredentialResolver
{
    Task<ProtectedCredential?> ResolveAsync(
        string providerKey,
        string resourceReference,
        CancellationToken ct = default);
}
