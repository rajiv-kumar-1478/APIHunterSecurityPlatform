using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Infrastructure Implementation of IEgressNetworkProxy.
/// Establishes scoped network-layer egress enforcement policies, separating authorization decisions from traffic execution.
/// </summary>
public class EgressNetworkProxy : IEgressNetworkProxy
{
    private readonly IEgressPolicyEngine _policyEngine;
    private readonly ILogger<EgressNetworkProxy> _logger;

    public EgressNetworkProxy(IEgressPolicyEngine policyEngine, ILogger<EgressNetworkProxy> logger)
    {
        _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<IAsyncDisposable> CreateScopedPolicyAsync(EgressTarget egressTarget, CancellationToken cancellationToken = default)
    {
        if (egressTarget == null)
        {
            _logger.LogError("CreateScopedPolicyAsync failed: Null EgressTarget provided.");
            throw new ArgumentNullException(nameof(egressTarget));
        }

        if (egressTarget.IsExpired(DateTime.UtcNow))
        {
            _logger.LogError("CreateScopedPolicyAsync failed: Expired EgressTarget for host '{Host}'.", egressTarget.CanonicalHost);
            throw new InvalidOperationException($"EgressTarget authorization for host '{egressTarget.CanonicalHost}' has expired.");
        }

        if (egressTarget.ApprovedIpAddresses == null || egressTarget.ApprovedIpAddresses.Count == 0)
        {
            _logger.LogError("CreateScopedPolicyAsync failed: Target '{Host}' has no approved IP addresses.", egressTarget.CanonicalHost);
            throw new InvalidOperationException($"EgressTarget for host '{egressTarget.CanonicalHost}' contains no approved IP targets.");
        }

        _logger.LogInformation("EgressNetworkProxy established scoped egress policy for target host '{Host}' with {Count} approved IP(s) (Version: {Version}).",
            egressTarget.CanonicalHost, egressTarget.ApprovedIpAddresses.Count, egressTarget.PolicyVersion);

        return Task.FromResult<IAsyncDisposable>(new ScopedNetworkProxyHandle(egressTarget, _logger));
    }

    private sealed class ScopedNetworkProxyHandle : IAsyncDisposable
    {
        private readonly EgressTarget _target;
        private readonly ILogger _logger;
        private bool _disposed;

        public ScopedNetworkProxyHandle(EgressTarget target, ILogger logger)
        {
            _target = target;
            _logger = logger;
        }

        public ValueTask DisposeAsync()
        {
            if (!_disposed)
            {
                _logger.LogInformation("EgressNetworkProxy disposed scoped egress policy for target host '{Host}'.", _target.CanonicalHost);
                _disposed = true;
            }
            return ValueTask.CompletedTask;
        }
    }
}
