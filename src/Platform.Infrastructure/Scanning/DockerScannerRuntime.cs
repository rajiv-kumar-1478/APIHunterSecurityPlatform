using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Containerized OCI/Docker Scanner Runtime Sandbox.
/// Enforces strong container isolation (CPU, Memory, PIDs, read-only root, dropped capabilities, no-new-privileges, scratch volume mount).
/// Enforces immutable container image provenance pinning (repository allowlist + sha256 digest) and routes container traffic through an Enforced Egress Gateway.
/// Fails closed with DOCKER_RUNTIME_UNAVAILABLE when RuntimeMode is LocalDocker or RequireDockerSandbox is true and Docker daemon is absent.
/// </summary>
public class DockerScannerRuntime : IScannerRuntimeSandbox
{
    private static readonly Regex ContainerNameRegex = new(@"^apihunter-[a-zA-Z0-9_\-]+$", RegexOptions.Compiled);
    private static readonly Regex DigestRegex = new(@"^sha256:[a-fA-F0-9]{64}$", RegexOptions.Compiled);

    private readonly ScannerRuntimeOptions _options;
    private readonly Func<string, IGenericCliToolAdapter> _cliAdapterFactory;
    private readonly IEnforcedEgressGateway _egressGateway;
    private readonly ILogger<DockerScannerRuntime> _logger;

    public DockerScannerRuntime(
        ScannerRuntimeOptions options,
        Func<string, IGenericCliToolAdapter> cliAdapterFactory,
        IEnforcedEgressGateway egressGateway,
        ILogger<DockerScannerRuntime> logger)
    {
        _options = options ?? new ScannerRuntimeOptions();
        _cliAdapterFactory = cliAdapterFactory ?? throw new ArgumentNullException(nameof(cliAdapterFactory));
        _egressGateway = egressGateway ?? throw new ArgumentNullException(nameof(egressGateway));
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

        if (cancellationToken.IsCancellationRequested)
        {
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Cancelled, -1, null, "EXECUTION_CANCELLED");
        }

        // 1. Fail Closed on Executable Missing / Unconfigured (No fallback to ToolKey)
        if (string.IsNullOrWhiteSpace(request.Executable))
        {
            _logger.LogError("DockerScannerRuntime execution rejected: Executable is missing or unconfigured for tool '{ToolKey}'.", request.ToolKey);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "TOOL_EXECUTABLE_NOT_CONFIGURED");
        }

        try
        {
            ScanToolRegistryService.ValidateExecutableName(request.Executable);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DockerScannerRuntime execution rejected: Executable name '{Executable}' failed security validation.", request.Executable);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "TOOL_EXECUTABLE_INVALID");
        }

        // 2. Fail Closed on Expired or Unapproved Egress Target Authorization
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

        // 3. Immutable Container Image Provenance Verification (Strict Fail-Closed)
        if (_options.EnforceImageProvenance)
        {
            var provenanceValid = ValidateImageProvenance(request, out var provenanceErrorCode);
            if (!provenanceValid)
            {
                _logger.LogError("DockerScannerRuntime execution rejected: Container image provenance verification failed for tool '{ToolKey}' ({ErrorCode}).",
                    request.ToolKey, provenanceErrorCode);
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, provenanceErrorCode);
            }
        }

        // 4. Scratch Directory Path Defense in Depth
        ValidateScratchMountPath(scratchDirectory, _options.PlatformScratchRoot);

        // 5. Establish Scoped Enforced Egress Gateway Session
        await using var gatewaySession = await _egressGateway.CreateScopedSessionAsync(egressTarget, cancellationToken);

        // 6. Build Docker Container Isolation Arguments deterministically
        var dockerArgs = BuildDockerIsolationArguments(request, egressTarget, gatewaySession, scratchDirectory);

        // 7. Verify Docker Daemon Availability
        var isDockerAvailable = IsDockerDaemonAvailable();
        if ((_options.RuntimeMode == ScannerRuntimeMode.LocalDocker || _options.RequireDockerSandbox) && !isDockerAvailable)
        {
            _logger.LogError("DockerScannerRuntime execution rejected: Docker runtime is required (RuntimeMode: {Mode}) but Docker daemon is unavailable.", _options.RuntimeMode);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "DOCKER_RUNTIME_UNAVAILABLE");
        }

        _logger.LogInformation("DockerScannerRuntime launching execution for tool '{ToolKey}' (v{Version}) with limits [CPU: {Cpu}, Memory: {Mem}B, PIDs: {Pids}].",
            request.ToolKey, request.Version, _options.MaxCpuCores, _options.MaxMemoryBytes, _options.MaxPids);

        // 8. Execute real `docker run` container if Docker daemon is active
        if (isDockerAvailable)
        {
            return await ExecuteDockerContainerAsync(request, egressTarget, dockerArgs, scratchDirectory, cancellationToken);
        }

        // 9. Fail Closed if Docker is unavailable (No host execution for LocalDocker or CloudManagedContainer)
        if (_options.RuntimeMode == ScannerRuntimeMode.UnsafeLocalProcessFallback && _options.AllowUnsafeProcessFallback)
        {
            _logger.LogWarning("DEVELOPMENT_MODE_REDUCED_ISOLATION: Running explicitly configured local process execution fallback.");
            var cliAdapter = _cliAdapterFactory(request.ToolKey);
            return await cliAdapter.ExecuteAsync(request, secretLease, scratchDirectory, cancellationToken);
        }

        _logger.LogError("DockerScannerRuntime execution rejected: Docker daemon is unavailable and host process fallback is disabled.");
        return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "DOCKER_RUNTIME_UNAVAILABLE");
    }

    public IReadOnlyList<string> BuildDockerIsolationArguments(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        IEnforcedEgressGatewaySession gatewaySession,
        string scratchDirectory)
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

        // Dedicated network isolation
        if (!string.IsNullOrWhiteSpace(gatewaySession?.NetworkName))
        {
            args.Add($"--network={gatewaySession.NetworkName}");
        }

        // Gateway environment variables (including NO_PROXY="")
        if (gatewaySession?.ContainerEnvironmentVariables != null)
        {
            foreach (var kvp in gatewaySession.ContainerEnvironmentVariables)
            {
                args.Add($"--env={kvp.Key}={kvp.Value}");
            }
        }

        var normalizedScratch = Path.GetFullPath(scratchDirectory);
        args.Add($"--volume={normalizedScratch}:/tmp/apihunter_scratch:rw");
        args.Add($"--env=APIHUNTER_SCAN_JOB_ID={request.ScanJobId:N}");

        return args.AsReadOnly();
    }

    private bool ValidateImageProvenance(ToolExecutionRequest request, out string errorCode)
    {
        if (string.IsNullOrWhiteSpace(request.ContainerImageRepository))
        {
            errorCode = "TOOL_PROVENANCE_NOT_VERIFIED: ContainerImageRepository is missing or unconfigured.";
            return false;
        }

        var repo = request.ContainerImageRepository.Trim();
        var isTrustedRegistry = _options.TrustedImageRegistries != null && _options.TrustedImageRegistries.Any(trusted =>
            repo.Equals(trusted, StringComparison.OrdinalIgnoreCase) ||
            repo.StartsWith(trusted + "/", StringComparison.OrdinalIgnoreCase));

        if (!isTrustedRegistry)
        {
            errorCode = $"TOOL_PROVENANCE_NOT_VERIFIED: ContainerImageRepository '{repo}' is not in the trusted registry allowlist.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(request.ContainerImageDigest))
        {
            errorCode = "TOOL_PROVENANCE_NOT_VERIFIED: ContainerImageDigest is missing. Immutable digest pin required.";
            return false;
        }

        var digest = request.ContainerImageDigest.Trim();
        if (!DigestRegex.IsMatch(digest))
        {
            errorCode = $"TOOL_PROVENANCE_NOT_VERIFIED: ContainerImageDigest '{digest}' does not match sha256 hexadecimal format.";
            return false;
        }

        errorCode = string.Empty;
        return true;
    }

    private async Task<ToolExecutionResult> ExecuteDockerContainerAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        IReadOnlyList<string> isolationArgs,
        string scratchDirectory,
        CancellationToken cancellationToken)
    {
        var containerName = $"apihunter-{request.ToolKey.ToLowerInvariant()}-{request.ScanJobId:N}";
        if (!ContainerNameRegex.IsMatch(containerName))
        {
            _logger.LogError("DockerScannerRuntime container name '{ContainerName}' failed format validation.", containerName);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "INVALID_CONTAINER_NAME");
        }

        if (string.IsNullOrWhiteSpace(request.ContainerImageRepository) || string.IsNullOrWhiteSpace(request.ContainerImageDigest))
        {
            _logger.LogError("DockerScannerRuntime container execution rejected: ContainerImageRepository and ContainerImageDigest are required (No fallback).");
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "TOOL_PROVENANCE_NOT_VERIFIED");
        }

        var imageSpec = $"{request.ContainerImageRepository.Trim()}@{request.ContainerImageDigest.Trim()}";

        var fullArgs = new List<string>(isolationArgs)
        {
            $"--name={containerName}",
            imageSpec,
            request.Executable!
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
            TryKillContainer(containerName);

            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Docker container execution for tool '{ToolKey}' was cancelled by user.", request.ToolKey);
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Cancelled, -1, null, "CANCELLED");
            }

            _logger.LogWarning("Docker container execution for tool '{ToolKey}' timed out after {Timeout}.", request.ToolKey, _options.ExecutionTimeout);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.TimedOut, -1, null, "DOCKER_CONTAINER_TIMEOUT");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to launch Docker container for tool '{ToolKey}'.", request.ToolKey);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, $"DOCKER_LAUNCH_FAILED: {ex.Message}");
        }
    }

    private static void ValidateScratchMountPath(string scratchDirectory, string platformScratchRoot)
    {
        if (string.IsNullOrWhiteSpace(scratchDirectory))
            throw new ArgumentException("Scratch directory path cannot be empty.", nameof(scratchDirectory));

        var fullPath = Path.GetFullPath(scratchDirectory);
        var canonicalRoot = Path.GetFullPath(platformScratchRoot);

        var prefix = canonicalRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

        if (!fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !fullPath.Equals(canonicalRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Scratch directory '{fullPath}' is outside approved root '{canonicalRoot}'.");
        }

        var dirInfo = new DirectoryInfo(fullPath);
        if (dirInfo.Exists && dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException($"Scratch directory '{fullPath}' contains a reparse point or symlink.");
        }
    }

    private static void TryKillContainer(string containerName)
    {
        try
        {
            if (!ContainerNameRegex.IsMatch(containerName))
            {
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = "docker",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("kill");
            psi.ArgumentList.Add(containerName);

            using var killProc = Process.Start(psi);
            killProc?.WaitForExit(3000);
        }
        catch
        {
            // Suppress secondary cleanup exceptions on cancellation
        }
    }

    public static bool IsDockerDaemonAvailable()
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
