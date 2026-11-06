using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Platform.Application.Configuration;
using Platform.Infrastructure.Adapters.Ssh;

namespace Platform.Infrastructure.Adapters.ApiHunter;

/// <summary>
/// Opens read-only connections to the external APIHunter database. When VPS SSH is configured the
/// database endpoint is reached through an SSH local-port-forward so the database never needs a
/// public listener.
/// </summary>
public sealed class SshTunneledApiHunterConnectionFactory : IApiHunterConnectionFactory
{
    private readonly string _connectionString;
    private readonly IVpsSshConnectionFactory _ssh;
    private readonly ILogger<SshTunneledApiHunterConnectionFactory> _logger;

    public SshTunneledApiHunterConnectionFactory(
        IOptions<ApiHunterSourceOptions> options,
        IConfiguration configuration,
        IVpsSshConnectionFactory ssh,
        ILogger<SshTunneledApiHunterConnectionFactory> logger)
    {
        _connectionString = ApiHunterConnectionStringResolver.Resolve(configuration, options.Value);
        _ssh = ssh;
        _logger = logger;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_connectionString);

    public async Task<ApiHunterDbConnection> OpenAsync(CancellationToken ct = default)
    {
        if (!IsConfigured)
            throw new InvalidOperationException("APIHunter source connection string is not configured.");

        var builder = new NpgsqlConnectionStringBuilder(_connectionString);
        SshTunnel? tunnel = null;

        if (_ssh.IsConfigured)
        {
            var remoteHost = builder.Host ?? throw new InvalidOperationException("APIHunter connection string has no Host.");
            var remotePort = builder.Port;
            tunnel = await _ssh.OpenTunnelAsync(remoteHost, remotePort, ct).ConfigureAwait(false);

            builder.Host = tunnel.LocalHost;
            builder.Port = tunnel.LocalPort;
            builder.SslMode = SslMode.Disable;
            builder.Timeout = Math.Max(builder.Timeout, 30);

            _logger.LogDebug("Tunneling APIHunter DB {RemoteHost}:{RemotePort} via SSH to {LocalHost}:{LocalPort}.",
                remoteHost, remotePort, tunnel.LocalHost, tunnel.LocalPort);
        }

        var connection = new NpgsqlConnection(builder.ConnectionString);
        try
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            return new ApiHunterDbConnection(connection, tunnel);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            if (tunnel is not null)
                await tunnel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
