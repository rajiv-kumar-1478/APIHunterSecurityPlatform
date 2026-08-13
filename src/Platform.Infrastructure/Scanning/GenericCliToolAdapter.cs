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
    private readonly string _scratchRoot;

    public string ToolKey { get; }

    public GenericCliToolAdapter(string toolKey, ILogger<GenericCliToolAdapter> logger, string? scratchRoot = null)
    {
        ToolKey = toolKey ?? throw new ArgumentNullException(nameof(toolKey));
        _logger = logger;
        _scratchRoot = scratchRoot ?? Path.Combine(Path.GetTempPath(), "apihunter_scans");
    }

    public async Task<ToolExecutionResult> ExecuteAsync(
        ToolExecutionRequest request,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Executable))
        {
            _logger.LogError("Tool execution request for '{ToolKey}' has no Executable property configured.", request.ToolKey);
            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.Failed,
                ExitCode: -1,
                ArtifactReference: null,
                ErrorCode: "TOOL_EXECUTABLE_NOT_CONFIGURED"
            );
        }

        var binaryName = request.Executable;

        // 1. Enforce Whitelisted Binary Execution Guard on (ToolKey, Executable) against AuthorizedManifest
        ValidateToolExecutableWhitelist(request.ToolKey, binaryName, request.AuthorizedManifest);

        // 2. Path Traversal & Symlink/Junction Filesystem Guard
        ValidateScratchDirectoryPath(scratchDirectory, _scratchRoot);

        Directory.CreateDirectory(scratchDirectory);
        VerifyNoReparsePointOrSymlink(scratchDirectory);
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

        // Inject tool arguments safely (CLI flag validation)
        if (request.Arguments != null)
        {
            foreach (var kvp in request.Arguments)
            {
                if (kvp.Key.StartsWith("-"))
                {
                    startInfo.ArgumentList.Add(kvp.Key);
                }
                else if (kvp.Key.Length == 1)
                {
                    startInfo.ArgumentList.Add($"/{kvp.Key}");
                }
                else
                {
                    startInfo.ArgumentList.Add($"--{kvp.Key}");
                }

                if (!string.IsNullOrWhiteSpace(kvp.Value))
                {
                    startInfo.ArgumentList.Add(kvp.Value);
                }
            }
        }

        // Environment Variable secret injection (Leased Secrets ONLY - NEVER in CLI args or DTOs)
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
            // Process completed without token cancellation
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
            // Explicit timeout or cancellation handling - terminate child process tree before returning
            KillProcessTreeSafely(process);

            var isExplicitCancel = ct.IsCancellationRequested;
            var errorCode = isExplicitCancel ? "CANCELLED" : "TIMED_OUT";

            _logger.LogWarning("Execution of CLI tool '{ToolKey}' was aborted ({ErrorCode}, Job: {ScanJobId}).", request.ToolKey, errorCode, request.ScanJobId);

            return new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.TimedOut,
                ExitCode: 124,
                ArtifactReference: null,
                ErrorCode: errorCode
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
            var sanitizedMessage = SanitizeOutput(ex.Message, secretLease);
            _logger.LogError(ex, "Unexpected error executing CLI tool '{ToolKey}': {Message}", request.ToolKey, sanitizedMessage);

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

    public static void ValidateToolExecutableWhitelist(string toolKey, string binaryName, IReadOnlyDictionary<string, string>? manifestMap = null)
    {
        // 1. Defense-in-depth trusted executable identifier rules (reject shell interpreters, path traversal, absolute paths)
        ScanToolRegistryService.ValidateExecutableName(binaryName);

        // 2. Validate against explicit manifest map (fail-closed if missing, ToolKey not present, or executable mismatch)
        if (manifestMap == null || manifestMap.Count == 0)
        {
            throw new InvalidOperationException("Security Violation: Authorized scanner tool manifest is missing or empty. Execution fail-closed.");
        }

        var normalizedKey = toolKey.Trim().ToLowerInvariant();
        if (!manifestMap.TryGetValue(normalizedKey, out var authorizedExecutable) || string.IsNullOrWhiteSpace(authorizedExecutable))
        {
            throw new InvalidOperationException($"Security Violation: ToolKey '{toolKey}' is not registered in the authorized scanner tool manifest.");
        }

        if (!string.Equals(authorizedExecutable.Trim(), binaryName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Security Violation: ToolKey '{toolKey}' is bound to executable '{authorizedExecutable}', but requested executable was '{binaryName}'. Execution rejected.");
        }
    }

    public static void ValidateScratchDirectoryPath(string path, string? scratchRoot = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Scratch directory path cannot be empty.", nameof(path));
        }

        var root = scratchRoot ?? Path.Combine(Path.GetTempPath(), "apihunter_scans");
        var canonicalScratch = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var canonicalRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        // Strict canonical path component anchoring check
        var isAnchored = canonicalScratch.Equals(canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
                         canonicalScratch.StartsWith(canonicalRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

        if (!isAnchored)
        {
            throw new InvalidOperationException($"Security Violation: Scratch directory '{canonicalScratch}' escapes allowed scratch root '{canonicalRoot}'.");
        }
    }

    public static void VerifyNoReparsePointOrSymlink(string directoryPath)
    {
        if (Directory.Exists(directoryPath))
        {
            var dirInfo = new DirectoryInfo(directoryPath);
            if ((dirInfo.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
            {
                throw new InvalidOperationException($"Security Violation: Scratch directory '{directoryPath}' is a symlink or junction point.");
            }
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
