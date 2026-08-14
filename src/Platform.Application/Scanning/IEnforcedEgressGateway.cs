using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

/// <summary>
/// Scoped enforcement session actively governing container outbound network egress.
/// </summary>
public interface IEnforcedEgressGatewaySession : IAsyncDisposable
{
    string NetworkName { get; }
    string GatewayEndpoint { get; }
    IReadOnlyDictionary<string, string> ContainerEnvironmentVariables { get; }
    bool ValidateOutboundConnection(IPAddress destinationIp, int port);
}

/// <summary>
/// Authoritative network egress enforcement gateway for container sandboxes.
/// Restricts all outbound container traffic strictly to validated and approved IP addresses.
/// </summary>
public interface IEnforcedEgressGateway
{
    Task<IEnforcedEgressGatewaySession> CreateScopedSessionAsync(
        EgressTarget egressTarget,
        CancellationToken cancellationToken = default);

    Task<bool> IsGatewayHealthyAsync(CancellationToken cancellationToken = default);
}
