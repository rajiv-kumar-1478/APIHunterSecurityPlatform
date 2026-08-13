using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;

namespace Platform.Infrastructure.Scanning;

public class ToolRuntimeVerifier : IToolRuntimeVerifier
{
    private readonly string _toolsRoot;
    private readonly ILogger<ToolRuntimeVerifier> _logger;

    public ToolRuntimeVerifier(ILogger<ToolRuntimeVerifier> logger, string? toolsRoot = null)
    {
        _logger = logger;
        _toolsRoot = toolsRoot ?? Path.Combine(Path.GetTempPath(), "apihunter_tools");
    }

    public async Task<ToolProbeResult> ProbeToolAsync(SecurityScanTool tool, CancellationToken ct = default)
    {
        if (tool == null) throw new ArgumentNullException(nameof(tool));

        var toolKey = tool.ToolKey.Trim().ToLowerInvariant();
        var version = tool.Version.Trim();
        var now = DateTime.UtcNow;

        _logger.LogInformation("Executing 4-stage runtime probe suite for tool '{ToolKey}'.", toolKey);

        // ─────────────────────────────────────────────────────────────────────
        // Stage 1: ExecutableExists Probe
        // ─────────────────────────────────────────────────────────────────────
        ScanToolRegistryService.ValidateExecutableName(tool.Executable);

        var resolvedBinary = ResolveExecutablePath(toolKey, version, tool.Executable);
        if (string.IsNullOrWhiteSpace(resolvedBinary))
        {
            _logger.LogWarning("Probe 'ExecutableExists' failed for '{ToolKey}': Binary '{Executable}' not found on disk.", toolKey, tool.Executable);
            return new ToolProbeResult(toolKey, false, "ExecutableExists", "FILE_NOT_FOUND", $"Executable '{tool.Executable}' was not found at canonical install location or system path.", now);
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stage 2: ExecutableIsRunnable Probe (--version execution)
        // ─────────────────────────────────────────────────────────────────────
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        var versionStartInfo = new ProcessStartInfo
        {
            FileName = resolvedBinary,
            ArgumentList = { "--version" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        string versionOutput;
        try
        {
            using var process = new Process { StartInfo = versionStartInfo };
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);

            await process.WaitForExitAsync(cts.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            versionOutput = (stdout + " " + stderr).Trim();

            if (process.ExitCode != 0)
            {
                _logger.LogWarning("Probe 'ExecutableIsRunnable' failed for '{ToolKey}' with exit code {ExitCode}.", toolKey, process.ExitCode);
                return new ToolProbeResult(toolKey, false, "ExecutableIsRunnable", $"NON_ZERO_EXIT_{process.ExitCode}", $"Process exited with code {process.ExitCode}", now);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Probe 'ExecutableIsRunnable' timed out for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, false, "ExecutableIsRunnable", "PROBE_TIMED_OUT", "Version probe execution exceeded 5-second timeout.", now);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Probe 'ExecutableIsRunnable' exception for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, false, "ExecutableIsRunnable", "EXECUTION_EXCEPTION", ex.Message, now);
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stage 3: ReportedVersionMatchesManifest Probe
        // ─────────────────────────────────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(tool.Version) && !string.Equals(tool.Version, "unverified", StringComparison.OrdinalIgnoreCase))
        {
            var expectedVersion = tool.Version.Trim().TrimStart('v');
            var match = Regex.Match(versionOutput, @"\b\d+\.\d+\.\d+\b");
            if (match.Success)
            {
                var actualVersion = match.Value;
                if (!string.Equals(actualVersion, expectedVersion, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Probe 'ReportedVersionMatchesManifest' failed for '{ToolKey}': Expected '{Expected}', reported '{Actual}'.", toolKey, expectedVersion, actualVersion);
                    return new ToolProbeResult(toolKey, false, "ReportedVersionMatchesManifest", "VERSION_DRIFT_DETECTED", $"Reported version '{actualVersion}' does not match expected '{expectedVersion}'", now);
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stage 4: CapabilitySupported Probe (--help dry-run execution)
        // ─────────────────────────────────────────────────────────────────────
        var helpStartInfo = new ProcessStartInfo
        {
            FileName = resolvedBinary,
            ArgumentList = { "--help" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var helpProcess = new Process { StartInfo = helpStartInfo };
            helpProcess.Start();

            var helpStdoutTask = helpProcess.StandardOutput.ReadToEndAsync(cts.Token);
            var helpStderrTask = helpProcess.StandardError.ReadToEndAsync(cts.Token);

            await helpProcess.WaitForExitAsync(cts.Token);

            var helpStdout = await helpStdoutTask;
            var helpStderr = await helpStderrTask;
            var helpOutput = (helpStdout + " " + helpStderr).Trim();

            if (string.IsNullOrWhiteSpace(helpOutput))
            {
                _logger.LogWarning("Probe 'CapabilitySupported' failed for '{ToolKey}': Empty help/capability output.", toolKey);
                return new ToolProbeResult(toolKey, false, "CapabilitySupported", "CAPABILITY_PROBE_EMPTY", "Capability dry-run probe returned empty output.", now);
            }

            _logger.LogInformation("All 4 runtime probes successfully passed for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, true, "CapabilitySupported", null, null, now);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Probe 'CapabilitySupported' exception for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, false, "CapabilitySupported", "CAPABILITY_PROBE_FAILED", ex.Message, now);
        }
    }

    private string? ResolveExecutablePath(string toolKey, string version, string executable)
    {
        // 1. Direct path check
        if (Path.IsPathRooted(executable) && File.Exists(executable))
        {
            return executable;
        }

        // 2. Installed tool directory check (/opt/apihunter/tools/<toolkey>/<version>/<executable>)
        var installedPath = Path.Combine(_toolsRoot, toolKey, version, executable);
        if (File.Exists(installedPath))
        {
            return installedPath;
        }

        // 3. System PATH check for binaries like 'dotnet'
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var paths = pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

        foreach (var path in paths)
        {
            try
            {
                var fullPath = Path.Combine(path, executable);
                if (File.Exists(fullPath))
                {
                    return fullPath;
                }

                if (OperatingSystem.IsWindows() && !executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    var exePath = fullPath + ".exe";
                    if (File.Exists(exePath))
                    {
                        return exePath;
                    }
                }
            }
            catch
            {
                // Suppress path resolution errors
            }
        }

        return null;
    }
}
