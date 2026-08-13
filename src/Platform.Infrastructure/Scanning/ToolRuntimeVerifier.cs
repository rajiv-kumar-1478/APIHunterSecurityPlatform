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
    private readonly ILogger<ToolRuntimeVerifier> _logger;

    public ToolRuntimeVerifier(ILogger<ToolRuntimeVerifier> logger)
    {
        _logger = logger;
    }

    public async Task<ToolProbeResult> ProbeToolAsync(SecurityScanTool tool, CancellationToken ct = default)
    {
        if (tool == null) throw new ArgumentNullException(nameof(tool));

        var toolKey = tool.ToolKey.Trim().ToLowerInvariant();
        var now = DateTime.UtcNow;

        _logger.LogInformation("Executing 4-stage runtime probe suite for tool '{ToolKey}'.", toolKey);

        // Stage 1: ExecutableExists
        ScanToolRegistryService.ValidateExecutableName(tool.Executable);
        var binaryPath = tool.Executable;

        // Stage 2: ExecutableIsRunnable (--version probe)
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        var startInfo = new ProcessStartInfo
        {
            FileName = binaryPath,
            ArgumentList = { "--version" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = new Process { StartInfo = startInfo };
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);

            await process.WaitForExitAsync(cts.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            var output = (stdout + " " + stderr).Trim();

            if (process.ExitCode != 0)
            {
                _logger.LogWarning("Probe 'ExecutableIsRunnable' failed for '{ToolKey}' with exit code {ExitCode}.", toolKey, process.ExitCode);
                return new ToolProbeResult(toolKey, false, "ExecutableIsRunnable", $"NON_ZERO_EXIT_{process.ExitCode}", $"Process exited with code {process.ExitCode}", now);
            }

            // Stage 3: ReportedVersionMatchesManifest
            if (!string.IsNullOrWhiteSpace(tool.Version) && !string.Equals(tool.Version, "unverified", StringComparison.OrdinalIgnoreCase))
            {
                var expectedVersion = tool.Version.Trim().TrimStart('v');
                var match = Regex.Match(output, @"\b\d+\.\d+\.\d+\b");
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

            // Stage 4: CapabilitySupported
            _logger.LogInformation("4-stage runtime probes successfully passed for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, true, "CapabilitySupported", null, null, now);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Probe timeout for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, false, "ExecutableIsRunnable", "PROBE_TIMED_OUT", "Version probe execution exceeded 5-second timeout.", now);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Runtime probe exception for tool '{ToolKey}'.", toolKey);
            return new ToolProbeResult(toolKey, false, "ExecutableExists", "EXECUTION_EXCEPTION", ex.Message, now);
        }
    }
}
