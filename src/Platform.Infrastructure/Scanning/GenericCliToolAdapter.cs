using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class GenericCliToolAdapter : IGenericCliToolAdapter
{
    private readonly ILogger<GenericCliToolAdapter> _logger;

    public string ToolKey { get; }

    public GenericCliToolAdapter(string toolKey, ILogger<GenericCliToolAdapter> logger)
    {
        ToolKey = toolKey ?? throw new ArgumentNullException(nameof(toolKey));
        _logger = logger;
    }

    public async Task<ToolExecutionResult> ExecuteAsync(
        ToolExecutionRequest request,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken ct = default)
    {
        // 1. Path Traversal Guard
        ValidateScratchDirectoryPath(scratchDirectory);

        Directory.CreateDirectory(scratchDirectory);

        var binaryName = GetBinaryFileName(request.ToolKey);
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(request.Timeout > TimeSpan.Zero ? request.Timeout : TimeSpan.FromMinutes(10));

        var startInfo = new ProcessStartInfo
        {
            FileName = binaryName,
            WorkingDirectory = scratchDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Inject tool arguments safely
        if (request.Arguments != null)
        {
            foreach (var kvp in request.Arguments)
            {
                startInfo.ArgumentList.Add($"--{kvp.Key}");
                if (!string.IsNullOrWhiteSpace(kvp.Value))
                {
                    startInfo.ArgumentList.Add(SanitizeArgumentValue(kvp.Value));
                }
            }
        }

        // Environment Variable secret injection (Leased Secrets ONLY)
        if (secretLease?.Secrets != null)
        {
            foreach (var (key, value) in secretLease.Secrets)
            {
                startInfo.EnvironmentVariables[key] = value;
            }
        }

        using var process = new Process { StartInfo = startInfo };

        try
        {
            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    stdoutBuilder.AppendLine(SanitizeOutput(e.Data, secretLease));
                }
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    stderrBuilder.AppendLine(SanitizeOutput(e.Data, secretLease));
                }
            };

            _logger.LogInformation("Starting CLI tool '{ToolKey}' (Job: {ScanJobId}) in '{ScratchDirectory}'.", request.ToolKey, request.ScanJobId, scratchDirectory);
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync(cts.Token);

            var exitCode = process.ExitCode;
            var status = exitCode == 0 ? ToolExecutionStatus.Success : ToolExecutionStatus.Failed;
            var artifactRef = Path.Combine(scratchDirectory, $"{request.ToolKey}_output.json");

            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: status,
                ExitCode: exitCode,
                ArtifactReference: File.Exists(artifactRef) ? artifactRef : null,
                ErrorCode: exitCode == 0 ? null : $"EXIT_CODE_{exitCode}"
            );
        }
        catch (OperationCanceledException)
        {
            KillProcessTreeSafely(process);
            _logger.LogWarning("Execution of CLI tool '{ToolKey}' timed out or was cancelled (Job: {ScanJobId}).", request.ToolKey, request.ScanJobId);

            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.TimedOut,
                ExitCode: 124,
                ArtifactReference: null,
                ErrorCode: ct.IsCancellationRequested ? "CANCELLED" : "TIMED_OUT"
            );
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
        {
            _logger.LogError("Tool binary '{ToolKey}' missing or not executable.", request.ToolKey);
            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.Failed,
                ExitCode: -1,
                ArtifactReference: null,
                ErrorCode: "BINARY_NOT_FOUND"
            );
        }
        catch (Exception ex)
        {
            KillProcessTreeSafely(process);
            _logger.LogError(ex, "Unexpected error executing CLI tool '{ToolKey}'.", request.ToolKey);
            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.Failed,
                ExitCode: -1,
                ArtifactReference: null,
                ErrorCode: "EXECUTION_ERROR"
            );
        }
    }

    public static void ValidateScratchDirectoryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Scratch directory path cannot be empty.", nameof(path));
        }

        if (path.Contains(".."))
        {
            throw new InvalidOperationException($"Security Violation: Path traversal attempt detected in scratch directory path '{path}'.");
        }

        var fullPath = Path.GetFullPath(path);
        var baseTmpPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "scans"));

        // Allow workspace scratch paths or temp scan paths
        if (!fullPath.StartsWith(baseTmpPath, StringComparison.OrdinalIgnoreCase) && !fullPath.Contains("APIHunterSecurityPlatform"))
        {
            throw new InvalidOperationException($"Security Violation: Scratch directory '{fullPath}' escapes allowed temp root '{baseTmpPath}'.");
        }
    }

    public static string SanitizeOutput(string raw, ProviderSecretLease? secretLease)
    {
        if (string.IsNullOrEmpty(raw)) return raw;
        var sanitized = raw;

        if (secretLease?.Secrets != null)
        {
            foreach (var (_, val) in secretLease.Secrets)
            {
                if (!string.IsNullOrEmpty(val) && val.Length > 3)
                {
                    sanitized = sanitized.Replace(val, "***MASKED_SECRET***");
                }
            }
        }

        return sanitized;
    }

    private static string GetBinaryFileName(string toolKey) => toolKey.ToLowerInvariant() switch
    {
        "subfinder" => "subfinder",
        "httpx" => "httpx",
        "katana" => "katana",
        "nuclei" => "nuclei",
        "bughunter" => "bughunter",
        _ => toolKey
    };

    private static string SanitizeArgumentValue(string value) => value.Replace(";", "").Replace("&", "").Replace("|", "").Replace("`", "");

    private static void KillProcessTreeSafely(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Suppress process cleanup errors
        }
    }
}
