using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Platform.Infrastructure.Security;

public class SsrfValidationResult
{
    public bool IsAllowed { get; set; }
    public string DenialReason { get; set; } = string.Empty;
    public List<IPAddress> ValidatedIpAddresses { get; set; } = new();
}

public class SsrfProtectionService
{
    private readonly ValidationEndpointRegistry _endpointRegistry;
    private readonly ILogger<SsrfProtectionService> _logger;

    public SsrfProtectionService(ValidationEndpointRegistry endpointRegistry, ILogger<SsrfProtectionService> logger)
    {
        _endpointRegistry = endpointRegistry ?? throw new ArgumentNullException(nameof(endpointRegistry));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<SsrfValidationResult> ValidateProviderRequestAsync(string providerName, string? candidateSuppliedUrl, CancellationToken ct = default)
    {
        // 1. Verify candidate-supplied URL is NOT used as authoritative destination
        if (!string.IsNullOrWhiteSpace(candidateSuppliedUrl))
        {
            _logger.LogWarning("Candidate-supplied target URL '{CandidateUrl}' was supplied but strictly rejected. Endpoint destination is server-controlled.", candidateSuppliedUrl);
        }

        // 2. Lookup allowlisted server endpoint
        if (!_endpointRegistry.IsProviderSupported(providerName))
        {
            return new SsrfValidationResult
            {
                IsAllowed = false,
                DenialReason = $"Provider '{providerName}' is unsupported or not allowlisted."
            };
        }

        var allowlistedUri = _endpointRegistry.GetAllowlistedEndpoint(providerName);
        return await ValidateUriAsync(allowlistedUri, ct);
    }

    public async Task<SsrfValidationResult> ValidateUriAsync(Uri targetUri, CancellationToken ct = default)
    {
        if (targetUri == null) return new SsrfValidationResult { IsAllowed = false, DenialReason = "Null URI" };

        if (!targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return new SsrfValidationResult { IsAllowed = false, DenialReason = "Only HTTPS scheme is allowed for validation." };
        }

        string host = targetUri.Host;

        // Block explicit hostname metadata strings
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
        {
            return new SsrfValidationResult { IsAllowed = false, DenialReason = $"Hostname '{host}' is blocked by security policy." };
        }

        // 3. Resolve ALL A & AAAA DNS records
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host, AddressFamily.Unspecified, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DNS resolution failed for hostname '{Host}'.", host);
            return new SsrfValidationResult { IsAllowed = false, DenialReason = $"DNS resolution failed for '{host}': {ex.Message}" };
        }

        if (addresses == null || addresses.Length == 0)
        {
            return new SsrfValidationResult { IsAllowed = false, DenialReason = $"No DNS IP addresses returned for host '{host}'." };
        }

        // 4. Validate ALL resolved IP addresses
        foreach (var ip in addresses)
        {
            if (IsBlockedIp(ip, out string reason))
            {
                _logger.LogWarning("SSRF Protection blocked host '{Host}' due to IP '{IP}': {Reason}", host, ip, reason);
                return new SsrfValidationResult
                {
                    IsAllowed = false,
                    DenialReason = $"Resolved IP address '{ip}' for host '{host}' is prohibited: {reason}"
                };
            }
        }

        return new SsrfValidationResult
        {
            IsAllowed = true,
            ValidatedIpAddresses = addresses.ToList()
        };
    }

    public SocketsHttpHandler CreatePinnedSsrfHandler(string providerName)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            EnableMultipleHttp2Connections = true,
            ConnectCallback = async (context, cancellationToken) =>
            {
                var host = context.DnsEndPoint.Host;
                var port = context.DnsEndPoint.Port;

                // Validate request and resolve IPs directly within ConnectCallback
                var validationResult = await ValidateProviderRequestAsync(providerName, null, cancellationToken);
                if (!validationResult.IsAllowed || !validationResult.ValidatedIpAddresses.Any())
                {
                    throw new HttpRequestException($"SSRF Protection blocked connection to '{host}': {validationResult.DenialReason}");
                }

                // Connect TCP socket directly to validated IP endpoint
                var targetIp = validationResult.ValidatedIpAddresses.First();
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

                try
                {
                    await socket.ConnectAsync(new IPEndPoint(targetIp, port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

        return handler;
    }

    public static bool IsBlockedIp(IPAddress ip, out string reason)
    {
        reason = string.Empty;

        // Unpack IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        var targetIp = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

        if (IPAddress.IsLoopback(targetIp))
        {
            reason = "Loopback address";
            return true;
        }

        if (targetIp.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = targetIp.GetAddressBytes();

            // 0.0.0.0/8 (This host on this network)
            if (bytes[0] == 0)
            {
                reason = "Unspecified 0.0.0.0/8 range";
                return true;
            }

            // 10.0.0.0/8 (RFC 1918 Private)
            if (bytes[0] == 10)
            {
                reason = "RFC 1918 Private range (10.0.0.0/8)";
                return true;
            }

            // 172.16.0.0/12 (RFC 1918 Private)
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                reason = "RFC 1918 Private range (172.16.0.0/12)";
                return true;
            }

            // 192.168.0.0/16 (RFC 1918 Private)
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                reason = "RFC 1918 Private range (192.168.0.0/16)";
                return true;
            }

            // 169.254.0.0/16 (Link-Local & Cloud Metadata 169.254.169.254)
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                reason = "Link-Local / Cloud Metadata range (169.254.0.0/16)";
                return true;
            }

            // 100.64.0.0/10 (CGNAT / Shared Address Space)
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            {
                reason = "CGNAT Shared Address Space (100.64.0.0/10)";
                return true;
            }

            // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
            if (bytes[0] >= 224)
            {
                reason = "Multicast or Reserved range (224.0.0.0+)";
                return true;
            }
        }
        else if (targetIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] bytes = targetIp.GetAddressBytes();

            // :: / ::1 (Unspecified & Loopback)
            if (IPAddress.IPv6Any.Equals(targetIp) || IPAddress.IPv6Loopback.Equals(targetIp))
            {
                reason = "IPv6 Loopback / Unspecified";
                return true;
            }

            // fe80::/10 (Link-Local IPv6)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
            {
                reason = "Link-Local IPv6 range (fe80::/10)";
                return true;
            }

            // fc00::/7 (Unique-Local IPv6 ULA)
            if ((bytes[0] & 0xfe) == 0xfc)
            {
                reason = "Unique-Local IPv6 ULA range (fc00::/7)";
                return true;
            }

            // ff00::/8 (Multicast IPv6)
            if (bytes[0] == 0xff)
            {
                reason = "Multicast IPv6 range (ff00::/8)";
                return true;
            }
        }

        return false;
    }
}
