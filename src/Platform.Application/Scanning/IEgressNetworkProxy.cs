using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IEgressNetworkProxy
{
    Task<IAsyncDisposable> CreateScopedPolicyAsync(
        EgressTarget egressTarget,
        CancellationToken cancellationToken = default);
}
