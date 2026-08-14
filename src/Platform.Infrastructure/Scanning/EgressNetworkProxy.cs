using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Backward-compatible adapter forwarding to EnforcedEgressGateway.
/// </summary>
public class EgressNetworkProxy : IEgressNetworkProxy
{
    private readonly EnforcedEgressGateway _gateway;

    public EgressNetworkProxy(IEgressPolicyEngine policyEngine, ILogger<EnforcedEgressGateway> logger)
    {
        _gateway = new EnforcedEgressGateway(policyEngine, new ScannerRuntimeOptions(), logger);
    }

    public EgressNetworkProxy(IEgressPolicyEngine policyEngine, ScannerRuntimeOptions options, ILogger<EnforcedEgressGateway> logger)
    {
        _gateway = new EnforcedEgressGateway(policyEngine, options, logger);
    }

    public Task<IEnforcedEgressGatewaySession> CreateScopedSessionAsync(EgressTarget egressTarget, CancellationToken cancellationToken = default)
    {
        return _gateway.CreateScopedSessionAsync(egressTarget, cancellationToken);
    }

    public Task<IAsyncDisposable> CreateScopedPolicyAsync(EgressTarget egressTarget, CancellationToken cancellationToken = default)
    {
        return _gateway.CreateScopedPolicyAsync(egressTarget, cancellationToken);
    }

    public Task<bool> IsGatewayHealthyAsync(CancellationToken cancellationToken = default)
    {
        return _gateway.IsGatewayHealthyAsync(cancellationToken);
    }
}
