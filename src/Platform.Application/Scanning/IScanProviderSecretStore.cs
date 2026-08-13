using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IScanProviderSecretStore
{
    Task<ProviderSecretStatus> GetStatusAsync(string providerKey, CancellationToken ct = default);

    Task<ProviderSecretLease> AcquireLeaseAsync(string providerKey, CancellationToken ct = default);
}
