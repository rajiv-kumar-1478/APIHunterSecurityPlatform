using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

/// <summary>
/// Legacy interface adapter for IEgressNetworkProxy mapping into IEnforcedEgressGateway.
/// </summary>
public interface IEgressNetworkProxy : IEnforcedEgressGateway
{
    Task<IAsyncDisposable> CreateScopedPolicyAsync(
        EgressTarget egressTarget,
        CancellationToken cancellationToken = default);
}
