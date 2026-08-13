using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;

namespace Platform.Infrastructure.Scanning;

public class EgressPolicyEngine : IEgressPolicyEngine
{
    private readonly Func<string, Task<IPAddress[]>> _dnsResolver;
    private readonly ILogger<EgressPolicyEngine> _logger;

    public EgressPolicyEngine(ILogger<EgressPolicyEngine> logger, Func<string, Task<IPAddress[]>>? dnsResolver = null)
    {
        _logger = logger;
        _dnsResolver = dnsResolver ?? (async host => await Dns.GetHostAddressesAsync(host));
    }

    public async Task<EgressTarget> EvaluateAndBuildTargetAsync(string targetUrl, TimeSpan? ttl = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(targetUrl))
        {
            throw new ArgumentException("Target URL cannot be empty.", nameof(targetUrl));
        }

        var normalizedUrl = targetUrl.Trim();
        if (!normalizedUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !normalizedUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            normalizedUrl = "https://" + normalizedUrl;
        }

        if (!Uri.TryCreate(normalizedUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Security Violation: Invalid target URL '{targetUrl}'.");
        }

        var host = uri.Host;
        var port = uri.Port;
        var scheme = uri.Scheme;
        var resolvedAddresses = new HashSet<IPAddress>();

        // Check if host is a literal IP address
        if (IPAddress.TryParse(host, out var literalIp))
        {
            ValidateAddress(literalIp);
            resolvedAddresses.Add(literalIp);
        }
        else
        {
            // Resolve host addresses via DNS (A and AAAA)
            try
            {
                var addresses = await _dnsResolver(host);
                if (addresses == null || addresses.Length == 0)
                {
                    throw new InvalidOperationException($"Security Violation: DNS resolution returned no IP addresses for host '{host}'.");
                }

                foreach (var addr in addresses)
                {
                    // Strict rule: Reject if ANY resolved address is prohibited
                    ValidateAddress(addr);
                    resolvedAddresses.Add(addr);
                }
            }
            catch (Exception ex) when (ex is not InvalidOperationException)
            {
                _logger.LogError(ex, "Failed to resolve DNS for host '{Host}'.", host);
                throw new InvalidOperationException($"Security Violation: DNS resolution failed for host '{host}': {ex.Message}", ex);
            }
        }

        var resolvedAt = DateTime.UtcNow;
        var effectiveTtl = ttl ?? TimeSpan.FromMinutes(10);
        var expiresAt = resolvedAt.Add(effectiveTtl);

        _logger.LogInformation("EgressTarget constructed for host '{Host}' with {Count} approved IP(s). Expires at {ExpiresAtUtc}.", host, resolvedAddresses.Count, expiresAt);

        return new EgressTarget(
            RawTargetUrl: targetUrl,
            CanonicalHost: host,
            Port: port,
            Scheme: scheme,
            ApprovedIpAddresses: resolvedAddresses,
            ResolvedAtUtc: resolvedAt,
            ExpiresAtUtc: expiresAt,
            PolicyVersion: "v1.0-strict"
        );
    }

    public void ValidateAddress(IPAddress address)
    {
        if (IsProhibitedAddress(address))
        {
            _logger.LogWarning("Security Violation: Prohibited egress IP '{Address}' detected.", address);
            throw new InvalidOperationException($"Security Violation: Target IP '{address}' belongs to a prohibited subnet (loopback, RFC 1918, RFC 4193, CGNAT, IMDS, or link-local).");
        }
    }

    public bool IsProhibitedAddress(IPAddress address)
    {
        if (address == null) return true;

        // Map IPv4-mapped IPv6 addresses to IPv4
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        // Loopback checks
        if (IPAddress.IsLoopback(address)) return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            byte b0 = bytes[0];
            byte b1 = bytes[1];

            // IPv4 Loopback: 127.0.0.0/8
            if (b0 == 127) return true;

            // 0.0.0.0/8 Reserved
            if (b0 == 0) return true;

            // RFC 1918 Private ranges:
            // 10.0.0.0/8
            if (b0 == 10) return true;
            // 172.16.0.0/12
            if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
            // 192.168.0.0/16
            if (b0 == 192 && b1 == 168) return true;

            // Carrier-Grade NAT (CGNAT RFC 6598): 100.64.0.0/10
            if (b0 == 100 && b1 >= 64 && b1 <= 127) return true;

            // Link-Local / APIPA / Cloud Metadata (IMDS): 169.254.0.0/16 (includes 169.254.169.254)
            if (b0 == 169 && b1 == 254) return true;

            // Multicast: 224.0.0.0/4
            if (b0 >= 224 && b0 <= 239) return true;

            // Reserved: 240.0.0.0/4
            if (b0 >= 240) return true;
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();

            // IPv6 Loopback ::1
            if (IPAddress.IPv6Loopback.Equals(address)) return true;

            // Unique Local Address (RFC 4193): fc00::/7 (b0 is 0xfc or 0xfd)
            if ((bytes[0] & 0xfe) == 0xfc) return true;

            // Link-Local Address: fe80::/10 (b0 is 0xfe, b1 & 0xc0 is 0x80)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return true;

            // Cloud Metadata IPv6: fd00:ec2::254
            if (bytes[0] == 0xfd && bytes[1] == 0x00 && bytes[2] == 0x0e && bytes[3] == 0xc2 &&
                bytes[14] == 0x02 && bytes[15] == 0x54) return true;

            // Multicast ff00::/8
            if (bytes[0] == 0xff) return true;
        }

        return false;
    }
}
