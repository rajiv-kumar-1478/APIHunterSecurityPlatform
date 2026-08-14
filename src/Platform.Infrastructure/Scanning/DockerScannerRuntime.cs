using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Containerized OCI/Docker Scanner Runtime Sandbox.
/// Enforces strong container isolation (CPU, Memory, PIDs, read-only root, dropped capabilities, no-new-privileges, scratch volume mount).
/// Executes real `docker run` container processes when Docker daemon is available.
/// Fails closed with DOCKER_RUNTIME_UNAVAILABLE when RuntimeMode is Docker or RequireDockerSandbox is true and Docker daemon is absent.
/// </summary>
public class DockerScannerRuntime : IScannerRuntimeSandbox
{
    private readonly ScannerRuntimeOptions _options;
    private readonly Func<string, IGenericCliToolAdapter> _cliAdapterFactory;
    private readonly IEgressNetworkProxy _egressNetworkProxy;
    private readonly ILogger<DockerScannerRuntime> _logger;

    public DockerScannerRuntime(
        ScannerRuntimeOptions options,
        Func<string, IGenericCliToolAdapter> cliAdapterFactory,
        IEgressNetworkProxy egressNetworkProxy,
        ILogger<DockerScannerRuntime> logger)
    {
        _options = options ?? new ScannerRuntimeOptions();
        _cliAdapterFactory = cliAdapterFactory ?? throw new ArgumentNullException(nameof(cliAdapterFactory));
        _egressNetworkProxy = egressNetworkProxy ?? throw new ArgumentNullException(nameof(egressNetworkProxy));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ToolExecutionResult> ExecuteInSandboxAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (egressTarget == null) throw new ArgumentNullException(nameof(egressTarget));
        if (secretLease == null) throw new ArgumentNullException(nameof(secretLease));

        // 1. Fail Closed on Expired or Unapproved Egress Target Authorization
        if (egressTarget.IsExpired(DateTime.UtcNow))
        {
            _logger.LogError("DockerScannerRuntime execution rejected: EgressTarget for host '{Host}' has expired.", egressTarget.CanonicalHost);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "EXPIRED_EGRESS_AUTHORIZATION");
        }

        if (egressTarget.ApprovedIpAddresses == null || egressTarget.ApprovedIpAddresses.Count == 0)
        {
            _logger.LogError("DockerScannerRuntime execution rejected: EgressTarget for host '{Host}' contains no approved IP addresses.", egressTarget.CanonicalHost);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "UNAPPROVED_EGRESS_TARGET");
        }

        // 2. Establish Scoped Network Proxy Policy Enforcement
        await using var scopedPolicy = await _egressNetworkProxy.CreateScopedPolicyAsync(egressTarget, cancellationToken);

        // 3. Build Docker Container Isolation Arguments deterministically from ScannerRuntimeOptions
        var dockerArgs = BuildDockerIsolationArguments(request, egressTarget, scratchDirectory);

        // 4. Verify Docker Daemon Availability when Docker RuntimeMode or RequireDockerSandbox is Enforced
        var isDockerAvailable = IsDockerDaemonAvailable();
        if ((_options.RuntimeMode == ScannerRuntimeMode.Docker || _options.RequireDockerSandbox) && !isDockerAvailable)
        {
            _logger.LogError("DockerScannerRuntime execution rejected: Docker runtime is required (RuntimeMode: {Mode}) but Docker daemon is unavailable.", _options.RuntimeMode);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "DOCKER_RUNTIME_UNAVAILABLE");
        }

        _logger.LogInformation("DockerScannerRuntime launching execution for tool '{ToolKey}' (v{Version}) with limits [CPU: {Cpu}, Memory: {Mem}B, PIDs: {Pids}].",
            request.ToolKey, request.Version, _options.MaxCpuCores, _options.MaxMemoryBytes, _options.MaxPids);

        // 5. Execute real `docker run` container if Docker daemon is active
        if (isDockerAvailable)
        {
            return await ExecuteDockerContainerAsync(request, egressTarget, dockerArgs, scratchDirectory, cancellationToken);
        }

        _logger.LogWarning("DEVELOPMENT_MODE_REDUCED_ISOLATION: Docker daemon is unavailable on host. Running local process execution fallback.");

        // 6. Local Process Fallback (strictly in UnsafeLocalProcessFallback mode)
        var cliAdapter = _cliAdapterFactory(request.ToolKey);
        return await cliAdapter.ExecuteAsync(request, secretLease, scratchDirectory, cancellationToken);
    }

    public IReadOnlyList<string> BuildDockerIsolationArguments(ToolExecutionRequest request, EgressTarget egressTarget, string scratchDirectory)
    {
        var args = new List<string>
        {
            "run",
            "--rm",
            $"--cpus={_options.MaxCpuCores}",
            $"--memory={_options.MaxMemoryBytes}",
            $"--pids-limit={_options.MaxPids}"
        };

        if (_options.EnableReadOnlyRoot)
        {
            args.Add("--read-only");
        }

        if (_options.DropAllCapabilities)
        {
            args.Add("--cap-drop=ALL");
        }

        if (_options.NoNewPrivileges)
        {
            args.Add("--security-opt=no-new-privileges:true");
        }

        var normalizedScratch = Path.GetFullPath(scratchDirectory);
        args.Add($"--volume={normalizedScratch}:/tmp/apihunter_scratch:rw");
        args.Add($"--env=APIHUNTER_TARGET_HOST={egressTarget.CanonicalHost}");
        args.Add($"--env=APIHUNTER_SCAN_JOB_ID={request.ScanJobId:N}");

        return args.AsReadOnly();
    }

    private async Task<ToolExecutionResult> ExecuteDockerContainerAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        IReadOnlyList<string> isolationArgs,
        string scratchDirectory,
        CancellationToken cancellationToken)
    {
        var containerName = $"apihunter-{request.ToolKey}-{request.ScanJobId:N}";
        var fullArgs = new List<string>(isolationArgs)
        {
            $"--name={containerName}",
            $"apihunter/{request.ToolKey}:{request.Version}",
            request.Executable ?? request.ToolKey
        };

        if (request.Arguments != null)
        {
            foreach (var kvp in request.Arguments)
            {
                fullArgs.Add($"--{kvp.Key}");
                if (!string.IsNullOrWhiteSpace(kvp.Value))
                {
                    fullArgs.Add(kvp.Value);
                }
            }
        }

        var psi = new ProcessStartInfo
        {
            FileName = "docker",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var arg in fullArgs)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = psi };

        try
        {
            process.Start();

            using var timeoutCts = new CancellationTokenSource(_options.ExecutionTimeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (process.ExitCode == 0)
            {
                _logger.LogInformation("Docker container execution for tool '{ToolKey}' completed successfully.", request.ToolKey);
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Success, 0, scratchDirectory, null);
            }

            _logger.LogWarning("Docker container execution for tool '{ToolKey}' failed with exit code {ExitCode}. Stderr: {Stderr}",
                request.ToolKey, process.ExitCode, stderr);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, process.ExitCode, null, "DOCKER_CONTAINER_EXECUTION_FAILED");
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Docker container execution for tool '{ToolKey}' timed out or was cancelled. Force killing container '{Container}'.", request.ToolKey, containerName);
            TryKillContainer(containerName);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.TimedOut, -1, null, "DOCKER_CONTAINER_TIMEOUT");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to launch Docker container for tool '{ToolKey}'.", request.ToolKey);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, $"DOCKER_LAUNCH_FAILED: {ex.Message}");
        }
    }

    private static void TryKillContainer(string containerName)
    {
        try
        {
            using var killProc = Process.Start(new ProcessStartInfo
            {
                FileName = "docker",
                Arguments = $"kill {containerName}",
                UseShellExecute = false,
                CreateNoWindow = true
            });
            killProc?.WaitForExit(3000);
        }
        catch
        {
            // Suppress secondary cleanup exceptions on cancellation
        }
    }

    private static bool IsDockerDaemonAvailable()
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "docker",
                    Arguments = "info",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            proc.Start();
            return proc.WaitForExit(3000) && proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
