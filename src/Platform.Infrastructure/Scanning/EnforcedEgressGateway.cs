using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Authoritative network egress enforcement gateway.
/// Enforces physical and logical network isolation for container sandboxes, ensuring
/// that unapproved destination IPs, private subnets (RFC 1918), IMDS endpoints (169.254.169.254),
/// loopback addresses, and DNS rebinding vectors are strictly denied at the gateway boundary.
/// </summary>
public class EnforcedEgressGateway : IEnforcedEgressGateway, IEgressNetworkProxy
{
    private readonly IEgressPolicyEngine _policyEngine;
    private readonly ScannerRuntimeOptions _options;
    private readonly ILogger<EnforcedEgressGateway> _logger;

    public EnforcedEgressGateway(
        IEgressPolicyEngine policyEngine,
        ScannerRuntimeOptions options,
        ILogger<EnforcedEgressGateway> logger)
    {
        _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
        _options = options ?? new ScannerRuntimeOptions();
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<IEnforcedEgressGatewaySession> CreateScopedSessionAsync(
        EgressTarget egressTarget,
        CancellationToken cancellationToken = default)
    {
        if (egressTarget == null)
        {
            _logger.LogError("CreateScopedSessionAsync rejected: Null EgressTarget provided.");
            throw new ArgumentNullException(nameof(egressTarget));
        }

        if (egressTarget.IsExpired(DateTime.UtcNow))
        {
            _logger.LogError("CreateScopedSessionAsync rejected: Expired EgressTarget for host '{Host}'.", egressTarget.CanonicalHost);
            throw new InvalidOperationException($"EgressTarget authorization for host '{egressTarget.CanonicalHost}' has expired.");
        }

        if (egressTarget.ApprovedIpAddresses == null || egressTarget.ApprovedIpAddresses.Count == 0)
        {
            _logger.LogError("CreateScopedSessionAsync rejected: Target '{Host}' has no approved IP addresses.", egressTarget.CanonicalHost);
            throw new InvalidOperationException($"EgressTarget for host '{egressTarget.CanonicalHost}' contains no approved IP targets.");
        }

        foreach (var ip in egressTarget.ApprovedIpAddresses)
        {
            if (_policyEngine.IsProhibitedAddress(ip))
            {
                _logger.LogError("CreateScopedSessionAsync rejected: Target IP '{IP}' violates prohibited address policy.", ip);
                throw new InvalidOperationException($"Target IP '{ip}' is in a prohibited network address range (private/IMDS/loopback).");
            }
        }

        if (_options.EgressGatewayMode == EgressGatewayMode.EnforcedGateway && string.IsNullOrWhiteSpace(_options.EgressGatewayEndpoint))
        {
            _logger.LogError("CreateScopedSessionAsync rejected: EgressGatewayEndpoint must be configured when EgressGatewayMode is EnforcedGateway.");
            throw new InvalidOperationException("EgressGatewayEndpoint deployment configuration is missing.");
        }

        var gatewayEndpoint = _options.EgressGatewayEndpoint?.Trim() ?? string.Empty;
        var networkName = string.IsNullOrWhiteSpace(_options.EgressNetworkName) ? "apihunter-sandbox-net" : _options.EgressNetworkName.Trim();
        var approvedIpsString = string.Join(",", egressTarget.ApprovedIpAddresses.Select(ip => ip.ToString()));

        var envVars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["HTTP_PROXY"] = gatewayEndpoint,
            ["HTTPS_PROXY"] = gatewayEndpoint,
            ["http_proxy"] = gatewayEndpoint,
            ["https_proxy"] = gatewayEndpoint,
            ["ALL_PROXY"] = gatewayEndpoint,
            ["all_proxy"] = gatewayEndpoint,
            ["NO_PROXY"] = "", // Strictly empty to prevent bypassing the gateway to hit host/internal interfaces
            ["no_proxy"] = "",
            ["APIHUNTER_EGRESS_TARGET"] = egressTarget.CanonicalHost,
            ["APIHUNTER_APPROVED_IPS"] = approvedIpsString,
            ["APIHUNTER_EGRESS_POLICY_VERSION"] = egressTarget.PolicyVersion
        };

        _logger.LogInformation("EnforcedEgressGateway established scoped session for host '{Host}' ({Count} approved IPs) routing via gateway '{Gateway}' on network '{Network}'.",
            egressTarget.CanonicalHost, egressTarget.ApprovedIpAddresses.Count, gatewayEndpoint, networkName);

        var session = new EnforcedEgressGatewaySession(
            networkName,
            gatewayEndpoint,
            envVars,
            egressTarget,
            _policyEngine,
            _logger
        );

        return Task.FromResult<IEnforcedEgressGatewaySession>(session);
    }

    public async Task<IAsyncDisposable> CreateScopedPolicyAsync(EgressTarget egressTarget, CancellationToken cancellationToken = default)
    {
        return await CreateScopedSessionAsync(egressTarget, cancellationToken);
    }

    public Task<bool> IsGatewayHealthyAsync(CancellationToken cancellationToken = default)
    {
        if (_options.EgressGatewayMode == EgressGatewayMode.None)
        {
            return Task.FromResult(true);
        }

        if (string.IsNullOrWhiteSpace(_options.EgressGatewayEndpoint))
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(Uri.TryCreate(_options.EgressGatewayEndpoint, UriKind.Absolute, out _));
    }

    private sealed class EnforcedEgressGatewaySession : IEnforcedEgressGatewaySession
    {
        public string NetworkName { get; }
        public string GatewayEndpoint { get; }
        public IReadOnlyDictionary<string, string> ContainerEnvironmentVariables { get; }

        private readonly EgressTarget _target;
        private readonly IEgressPolicyEngine _policyEngine;
        private readonly ILogger _logger;
        private bool _disposed;

        public EnforcedEgressGatewaySession(
            string networkName,
            string gatewayEndpoint,
            IReadOnlyDictionary<string, string> containerEnvironmentVariables,
            EgressTarget target,
            IEgressPolicyEngine policyEngine,
            ILogger logger)
        {
            NetworkName = networkName;
            GatewayEndpoint = gatewayEndpoint;
            ContainerEnvironmentVariables = containerEnvironmentVariables;
            _target = target;
            _policyEngine = policyEngine;
            _logger = logger;
        }

        public bool ValidateOutboundConnection(IPAddress destinationIp, int port)
        {
            if (_disposed || _target.IsExpired(DateTime.UtcNow))
            {
                _logger.LogWarning("Outbound connection rejected: Gateway session is disposed or expired for target '{Host}'.", _target.CanonicalHost);
                return false;
            }

            if (_policyEngine.IsProhibitedAddress(destinationIp))
            {
                _logger.LogWarning("Outbound connection blocked: Destination IP '{IP}' is prohibited (private/IMDS/loopback).", destinationIp);
                return false;
            }

            if (!_target.ApprovedIpAddresses.Contains(destinationIp))
            {
                _logger.LogWarning("Outbound connection blocked: Destination IP '{IP}' is NOT in approved IP set for target '{Host}'.", destinationIp, _target.CanonicalHost);
                return false;
            }

            return true;
        }

        public ValueTask DisposeAsync()
        {
            if (!_disposed)
            {
                _logger.LogInformation("EnforcedEgressGateway session closed for target host '{Host}'.", _target.CanonicalHost);
                _disposed = true;
            }
            return ValueTask.CompletedTask;
        }
    }
}
