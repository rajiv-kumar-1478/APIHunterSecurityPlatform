using System;
using System.Linq;
using System.Net;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;

namespace Platform.Infrastructure.Scanning;

public class EgressProxyPolicy : IEgressProxyPolicy
{
    private readonly IEgressPolicyEngine _policyEngine;
    private readonly ILogger<EgressProxyPolicy> _logger;

    public EgressProxyPolicy(IEgressPolicyEngine policyEngine, ILogger<EgressProxyPolicy> logger)
    {
        _policyEngine = policyEngine;
        _logger = logger;
    }

    public bool ValidateConnectionRequest(EgressTarget target, IPAddress destinationIp, int port)
    {
        if (target == null)
        {
            _logger.LogError("Connection request rejected: EgressTarget is null.");
            return false;
        }

        if (target.IsExpired())
        {
            _logger.LogWarning("Connection request rejected: EgressTarget for host '{Host}' has expired.", target.CanonicalHost);
            return false;
        }

        if (_policyEngine.IsProhibitedAddress(destinationIp))
        {
            _logger.LogWarning("Connection request rejected: Destination IP '{IP}' is prohibited.", destinationIp);
            return false;
        }

        if (!target.ApprovedIpAddresses.Contains(destinationIp))
        {
            _logger.LogWarning("Connection request rejected: Destination IP '{IP}' is not in approved set for target '{Host}'.", destinationIp, target.CanonicalHost);
            return false;
        }

        return true;
    }

    public bool ValidateRedirectTarget(EgressTarget target, string redirectUrl, out IPAddress? resolvedIp)
    {
        resolvedIp = null;
        if (target == null || target.IsExpired())
        {
            _logger.LogWarning("Redirect validation failed: Null or expired EgressTarget.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(redirectUrl))
        {
            _logger.LogWarning("Redirect validation failed: Empty redirect URL.");
            return false;
        }

        if (!Uri.TryCreate(redirectUrl, UriKind.Absolute, out var uri))
        {
            _logger.LogWarning("Redirect validation failed: Invalid redirect URI '{RedirectUrl}'.", redirectUrl);
            return false;
        }

        if (IPAddress.TryParse(uri.Host, out var literalIp))
        {
            resolvedIp = literalIp;
            if (_policyEngine.IsProhibitedAddress(literalIp))
            {
                _logger.LogWarning("Redirect validation failed: Literal redirect IP '{IP}' is prohibited.", literalIp);
                return false;
            }
            return true;
        }

        // For hostnames, check if hostname matches canonical host or resolve IP
        try
        {
            var addresses = Dns.GetHostAddresses(uri.Host);
            if (addresses == null || addresses.Length == 0)
            {
                return false;
            }

            foreach (var addr in addresses)
            {
                if (_policyEngine.IsProhibitedAddress(addr))
                {
                    _logger.LogWarning("Redirect validation failed: Resolved IP '{IP}' for redirect host '{Host}' is prohibited.", addr, uri.Host);
                    return false;
                }
            }

            resolvedIp = addresses.FirstOrDefault();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve redirect host '{Host}'.", uri.Host);
            return false;
        }
    }
}
