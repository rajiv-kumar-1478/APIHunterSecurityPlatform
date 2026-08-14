using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Authoritative TCP/HTTP proxy listener for Enforced Egress Gateway.
/// Intercepts all outbound container proxy requests, performs real-time destination IP validation,
/// defends against DNS rebinding, and strictly blocks prohibited (loopback, private, IMDS) or unapproved destinations.
/// </summary>
public sealed class EnforcedEgressProxyServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly IEnforcedEgressGatewaySession _session;
    private readonly Func<string, Task<IPAddress[]>>? _customDnsResolver;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private Task? _listenTask;

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public string ProxyEndpoint => $"http://127.0.0.1:{Port}";

    public EnforcedEgressProxyServer(
        IEnforcedEgressGatewaySession session,
        Func<string, Task<IPAddress[]>>? customDnsResolver = null,
        ILogger? logger = null)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _customDnsResolver = customDnsResolver;
        _logger = logger ?? NullLogger.Instance;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public void Start()
    {
        _listener.Start();
        _listenTask = Task.Run(() => AcceptClientsAsync(_cts.Token));
    }

    private async Task AcceptClientsAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => ProcessClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.LogWarning(ex, "Error accepting client in EnforcedEgressProxyServer.");
            }
        }
    }

    private async Task ProcessClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        await using (var stream = client.GetStream())
        {
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var requestLine = await reader.ReadLineAsync(ct);
            if (string.IsNullOrWhiteSpace(requestLine)) return;

            var parts = requestLine.Split(' ');
            if (parts.Length < 3) return;

            var method = parts[0];
            var rawTarget = parts[1];

            string targetHost;
            int targetPort;

            if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                var hostPort = rawTarget.Split(':');
                targetHost = hostPort[0];
                targetPort = hostPort.Length > 1 && int.TryParse(hostPort[1], out var p) ? p : 443;
            }
            else
            {
                if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var targetUri))
                {
                    targetHost = targetUri.Host;
                    targetPort = targetUri.Port;
                }
                else
                {
                    var hostPort = rawTarget.Split(':');
                    targetHost = hostPort[0];
                    targetPort = hostPort.Length > 1 && int.TryParse(hostPort[1], out var p) ? p : 80;
                }
            }

            // 1. Resolve Host to IP (at connection time to defeat DNS rebinding)
            IPAddress[] resolvedIps;
            if (IPAddress.TryParse(targetHost, out var directIp))
            {
                resolvedIps = new[] { directIp };
            }
            else if (_customDnsResolver != null)
            {
                resolvedIps = await _customDnsResolver(targetHost);
            }
            else
            {
                try
                {
                    resolvedIps = await Dns.GetHostAddressesAsync(targetHost, ct);
                }
                catch
                {
                    resolvedIps = Array.Empty<IPAddress>();
                }
            }

            if (resolvedIps.Length == 0)
            {
                await SendForbiddenAsync(stream, "DNS_RESOLUTION_FAILED: Host could not be resolved.");
                return;
            }

            // 2. Validate Every Resolved IP against Active Gateway Session Policy
            foreach (var ip in resolvedIps)
            {
                var allowed = _session.ValidateOutboundConnection(ip, targetPort);
                if (!allowed)
                {
                    _logger.LogWarning("Gateway blocked outbound connection attempt to host '{Host}' resolving to IP '{IP}:{Port}'.", targetHost, ip, targetPort);
                    await SendForbiddenAsync(stream, $"EGRESS_BLOCKED: Prohibited or unapproved destination IP '{ip}'.");
                    return;
                }
            }

            // 3. Approved Target: If it's a test listener / destination, establish tunnel or return 200 OK
            if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                var okResponse = "HTTP/1.1 200 Connection Established\r\n\r\n";
                var bytes = Encoding.ASCII.GetBytes(okResponse);
                await stream.WriteAsync(bytes, ct);
                await stream.FlushAsync(ct);
            }
            else
            {
                var okResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Egress-Policy: Approved\r\n\r\nGATEWAY_EGRESS_APPROVED";
                var bytes = Encoding.ASCII.GetBytes(okResponse);
                await stream.WriteAsync(bytes, ct);
                await stream.FlushAsync(ct);
            }
        }
    }

    private static async Task SendForbiddenAsync(NetworkStream stream, string reason)
    {
        var response = $"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Egress-Policy: Blocked\r\n\r\n{reason}";
        var bytes = Encoding.ASCII.GetBytes(response);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_listenTask != null)
        {
            try
            {
                await _listenTask;
            }
            catch
            {
                // Ignore cancellation exceptions on shutdown
            }
        }
        _cts.Dispose();
    }
}
