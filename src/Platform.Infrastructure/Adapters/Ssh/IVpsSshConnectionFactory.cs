using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.Ssh;

public record RemoteCommandResult(int ExitCode, string StandardOutput, string StandardError);

public sealed class SshTunnel : IAsyncDisposable
{
    private readonly Renci.SshNet.SshClient _client;
    private readonly Renci.SshNet.ForwardedPortLocal _port;

    internal SshTunnel(Renci.SshNet.SshClient client, Renci.SshNet.ForwardedPortLocal port)
    {
        _client = client;
        _port = port;
        LocalPort = (int)port.BoundPort;
    }

    public string LocalHost { get; } = "127.0.0.1";
    public int LocalPort { get; }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await Task.Run(() =>
            {
                try { _port.Stop(); } catch { }
                try { _port.Dispose(); } catch { }
                try { _client.Disconnect(); } catch { }
                try { _client.Dispose(); } catch { }
            }).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // SSH.NET teardown can block on a half-open transport; do not hold up the caller.
        }
    }
}

public interface IVpsSshConnectionFactory
{
    bool IsConfigured { get; }

    Task<SshTunnel> OpenTunnelAsync(string remoteHost, int remotePort, CancellationToken ct = default);

    Task<RemoteCommandResult> ExecuteAsync(string command, CancellationToken ct = default);

    Task<Stream> DownloadFileAsync(string remotePath, CancellationToken ct = default);

    Task UploadFileAsync(string remotePath, Stream content, CancellationToken ct = default);

    Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default);
}
