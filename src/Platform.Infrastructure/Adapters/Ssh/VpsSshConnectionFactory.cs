using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Platform.Infrastructure.Adapters.Ssh;

public sealed class VpsSshConnectionFactory : IVpsSshConnectionFactory
{
    private readonly VpsSshOptions _options;
    private readonly ILogger<VpsSshConnectionFactory> _logger;

    public VpsSshConnectionFactory(IOptions<VpsSshOptions> options, ILogger<VpsSshConnectionFactory> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool IsConfigured =>
        _options.Enabled &&
        !string.IsNullOrWhiteSpace(_options.Host) &&
        !string.IsNullOrWhiteSpace(_options.Username) &&
        !string.IsNullOrWhiteSpace(_options.PrivateKeyPath) &&
        File.Exists(_options.PrivateKeyPath);

    public Task<SshTunnel> OpenTunnelAsync(string remoteHost, int remotePort, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(remoteHost);
        if (remotePort <= 0 || remotePort > 65535)
            throw new ArgumentOutOfRangeException(nameof(remotePort));

        ct.ThrowIfCancellationRequested();
        var client = CreateConnectedClient();
        var port = new ForwardedPortLocal("127.0.0.1", 0, remoteHost, (uint)remotePort);
        try
        {
            client.AddForwardedPort(port);
            port.Start();
            return Task.FromResult(new SshTunnel(client, port));
        }
        catch
        {
            try { port.Dispose(); } catch { }
            client.Dispose();
            throw;
        }
    }

    public async Task<RemoteCommandResult> ExecuteAsync(string command, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        using var client = CreateConnectedClient();
        using var sshCommand = client.CreateCommand(command);
        sshCommand.CommandTimeout = TimeSpan.FromSeconds(Math.Max(1, _options.CommandTimeoutSeconds));

        try
        {
            await sshCommand.ExecuteAsync(ct).ConfigureAwait(false);
            return new RemoteCommandResult(sshCommand.ExitStatus ?? -1, sshCommand.Result ?? string.Empty, sshCommand.Error ?? string.Empty);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new RemoteCommandResult(sshCommand.ExitStatus ?? -1, sshCommand.Result ?? string.Empty, sshCommand.Error ?? ex.Message);
        }
    }

    public async Task<Stream> DownloadFileAsync(string remotePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(remotePath);

        using var client = CreateConnectedClient();
        using var sftp = new SftpClient(client.ConnectionInfo);
        sftp.Connect();

        var tempPath = Path.Combine(Path.GetTempPath(), $"apihunter-{Guid.NewGuid():N}.tar.gz");
        try
        {
            await using (var file = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await Task.Run(() => sftp.DownloadFile(remotePath, file), ct).ConfigureAwait(false);
            }

            var length = new FileInfo(tempPath).Length;
            if (length <= 0)
                throw new InvalidOperationException($"Downloaded archive '{remotePath}' is empty.");
            if (_options.MaxArchiveBytes > 0 && length > _options.MaxArchiveBytes)
                throw new InvalidOperationException(
                    $"Downloaded archive '{remotePath}' is {length} bytes, exceeding the {_options.MaxArchiveBytes} byte limit.");

            return new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.DeleteOnClose);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    public async Task UploadFileAsync(string remotePath, Stream content, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(remotePath);
        ArgumentNullException.ThrowIfNull(content);

        using var client = CreateConnectedClient();
        using var sftp = new SftpClient(client.ConnectionInfo);
        sftp.Connect();

        await Task.Run(() => sftp.UploadFile(content, remotePath, canOverride: true), ct).ConfigureAwait(false);
    }

    public async Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            if (!IsConfigured)
                return new ComponentHealthResult("VpsSsh", false, "Unhealthy", "VPS SSH is not configured or the private key file is missing.", sw.Elapsed);

            var git = await ExecuteAsync($"{ShellQuote(_options.GitBinaryPath)} --version", ct).ConfigureAwait(false);
            if (git.ExitCode != 0)
                return new ComponentHealthResult("VpsSsh", false, "Unhealthy", $"git not available: {git.StandardError}", sw.Elapsed);

            var workDir = await ExecuteAsync($"mkdir -p {ShellQuote(_options.RemoteWorkDir)} && test -w {ShellQuote(_options.RemoteWorkDir)}", ct).ConfigureAwait(false);
            if (workDir.ExitCode != 0)
                return new ComponentHealthResult("VpsSsh", false, "Unhealthy", $"remote work dir not writable: {workDir.StandardError}", sw.Elapsed);

            return new ComponentHealthResult("VpsSsh", true, "Healthy", git.StandardOutput.Trim(), sw.Elapsed);
        }
        catch (Exception ex)
        {
            return new ComponentHealthResult("VpsSsh", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }

    internal static string ShellQuote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";

    private SshClient CreateConnectedClient()
    {
        if (!IsConfigured)
            throw new InvalidOperationException("VPS SSH is not configured. Set VpsSsh:Enabled and a valid VpsSsh:PrivateKeyPath.");

        var keyFile = string.IsNullOrEmpty(_options.PrivateKeyPassphrase)
            ? new PrivateKeyFile(_options.PrivateKeyPath)
            : new PrivateKeyFile(_options.PrivateKeyPath, _options.PrivateKeyPassphrase);

        var connectionInfo = new ConnectionInfo(
            _options.Host,
            _options.Port <= 0 ? 22 : _options.Port,
            _options.Username,
            new PrivateKeyAuthenticationMethod(_options.Username, keyFile))
        {
            Timeout = TimeSpan.FromSeconds(Math.Max(1, _options.ConnectTimeoutSeconds))
        };

        var client = new SshClient(connectionInfo);
        client.HostKeyReceived += OnHostKeyReceived;
        try
        {
            client.Connect();
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private void OnHostKeyReceived(object? sender, HostKeyEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_options.HostKeyFingerprint))
        {
            _logger.LogWarning("VPS SSH host-key pinning is disabled. Set VpsSsh:HostKeyFingerprint to prevent MITM.");
            return;
        }

        var actual = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
        if (!string.Equals(actual, _options.HostKeyFingerprint.Trim(), StringComparison.Ordinal))
        {
            _logger.LogError("VPS SSH host-key mismatch. Expected {Expected}, got {Actual}.", _options.HostKeyFingerprint, actual);
            e.CanTrust = false;
            return;
        }

        e.CanTrust = true;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // best effort cleanup
        }
    }
}
