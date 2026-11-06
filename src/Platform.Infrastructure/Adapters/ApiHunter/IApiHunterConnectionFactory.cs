using Npgsql;
using Platform.Infrastructure.Adapters.Ssh;

namespace Platform.Infrastructure.Adapters.ApiHunter;

public interface IApiHunterConnectionFactory
{
    bool IsConfigured { get; }
    Task<ApiHunterDbConnection> OpenAsync(CancellationToken ct = default);
}

public sealed class ApiHunterDbConnection : IAsyncDisposable
{
    private readonly SshTunnel? _tunnel;

    internal ApiHunterDbConnection(NpgsqlConnection connection, SshTunnel? tunnel)
    {
        Connection = connection;
        _tunnel = tunnel;
    }

    public NpgsqlConnection Connection { get; }

    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync().ConfigureAwait(false);
        if (_tunnel is not null)
            await _tunnel.DisposeAsync().ConfigureAwait(false);
    }
}
