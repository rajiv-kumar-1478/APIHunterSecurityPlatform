using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Infrastructure.Scanning;

public class ToolProvisioningService : IToolProvisioningService
{
    private readonly string _toolsRoot;
    private readonly Func<SecurityScanTool, CancellationToken, Task<Stream>> _artifactDownloader;
    private readonly ILogger<ToolProvisioningService> _logger;

    private static readonly HashSet<string> AllowedSourceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "github-release", "s3", "internal-registry", "official-release"
    };

    private static readonly HashSet<string> AllowedRepositories = new(StringComparer.OrdinalIgnoreCase)
    {
        "projectdiscovery/subfinder",
        "projectdiscovery/httpx",
        "projectdiscovery/katana",
        "projectdiscovery/nuclei",
        "owasp-amass/amass",
        "apihunter/bughunter"
    };

    public ToolProvisioningService(
        ILogger<ToolProvisioningService> logger,
        string? toolsRoot = null,
        Func<SecurityScanTool, CancellationToken, Task<Stream>>? artifactDownloader = null)
    {
        _logger = logger;
        _toolsRoot = toolsRoot ?? Path.Combine(Path.GetTempPath(), "apihunter_tools");
        _artifactDownloader = artifactDownloader ?? DefaultDownloadArtifactStreamAsync;
    }

    public async Task<ProvisioningResult> ProvisionToolAsync(SecurityScanTool tool, CancellationToken ct = default)
    {
        if (tool == null) throw new ArgumentNullException(nameof(tool));

        var toolKey = tool.ToolKey.Trim().ToLowerInvariant();
        var version = tool.Version.Trim();
        var expectedHash = tool.ArtifactSha256?.Trim().ToLowerInvariant() ?? string.Empty;

        _logger.LogInformation("Beginning provisioning evaluation for tool '{ToolKey}' (v{Version}).", toolKey, version);

        // 1. Verify Artifact Source Type against Trusted Provenance Policy
        if (string.IsNullOrWhiteSpace(tool.ArtifactSourceType) || !AllowedSourceTypes.Contains(tool.ArtifactSourceType))
        {
            _logger.LogError("Tool '{ToolKey}' specifies untrusted or missing ArtifactSourceType '{SourceType}'.", toolKey, tool.ArtifactSourceType);
            return new ProvisioningResult(toolKey, version, false, string.Empty, "UNTRUSTED_ARTIFACT_SOURCE", $"Artifact source type '{tool.ArtifactSourceType}' is prohibited.");
        }

        // 2. Verify Artifact Repository against Allowlisted Repositories
        if (string.IsNullOrWhiteSpace(tool.ArtifactRepository) || !AllowedRepositories.Contains(tool.ArtifactRepository))
        {
            _logger.LogError("Tool '{ToolKey}' specifies unapproved repository '{Repo}'.", toolKey, tool.ArtifactRepository);
            return new ProvisioningResult(toolKey, version, false, string.Empty, "UNAPPROVED_REPOSITORY", $"Artifact repository '{tool.ArtifactRepository}' is not in allowed registry.");
        }

        // 3. Verify SHA-256 Digest Presence
        if (string.IsNullOrWhiteSpace(expectedHash))
        {
            _logger.LogError("Tool '{ToolKey}' lacks mandatory ArtifactSha256 integrity hash.", toolKey);
            return new ProvisioningResult(toolKey, version, false, string.Empty, "MISSING_ARTIFACT_SHA256", "Mandatory ArtifactSha256 digest is missing.");
        }

        // 4. Construct Target Installation Directory
        var toolDir = Path.Combine(_toolsRoot, toolKey, version);
        Directory.CreateDirectory(toolDir);

        var executablePath = Path.Combine(toolDir, tool.Executable);

        // 5. Check if binary already exists locally with matching SHA-256
        if (File.Exists(executablePath))
        {
            var calculatedCacheHash = await ComputeFileSha256Async(executablePath, ct);
            if (string.Equals(calculatedCacheHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("Tool '{ToolKey}' binary verified in local cache with matching SHA-256 ({Hash}).", toolKey, calculatedCacheHash);
                return new ProvisioningResult(toolKey, version, true, executablePath, null, null);
            }

            _logger.LogWarning("Cached binary for '{ToolKey}' failed SHA-256 integrity check. Re-provisioning required.", toolKey);
            File.Delete(executablePath);
        }

        // 6. Real Artifact Download & Stream SHA-256 Computation
        var tempFile = Path.Combine(toolDir, $"{toolKey}_{version}_{Guid.NewGuid():N}.tmp");
        try
        {
            _logger.LogInformation("Downloading artifact stream for '{ToolKey}'...", toolKey);
            await using (var artifactStream = await _artifactDownloader(tool, ct))
            {
                if (artifactStream == null)
                {
                    throw new InvalidOperationException("Artifact stream provider returned null stream.");
                }

                await using var fileStream = File.Create(tempFile);
                await artifactStream.CopyToAsync(fileStream, ct);
            }

            // 7. Verify Downloaded Artifact SHA-256 Stream Hash
            var downloadedHash = await ComputeFileSha256Async(tempFile, ct);
            if (!string.Equals(downloadedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Checksum Mismatch for '{ToolKey}': Expected '{Expected}', calculated '{Calculated}'. Installation aborted.",
                    toolKey, expectedHash, downloadedHash);

                File.Delete(tempFile);
                return new ProvisioningResult(toolKey, version, false, string.Empty, "CHECKSUM_MISMATCH", $"Downloaded artifact SHA-256 '{downloadedHash}' does not match expected '{expectedHash}'.");
            }

            // 8. Atomic Installation Move & Verification
            if (File.Exists(executablePath))
            {
                File.Delete(executablePath);
            }
            File.Move(tempFile, executablePath);

            var installedHash = await ComputeFileSha256Async(executablePath, ct);
            if (!string.Equals(installedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(executablePath);
                return new ProvisioningResult(toolKey, version, false, string.Empty, "INSTALLED_HASH_MISMATCH", "Installed executable failed post-installation SHA-256 validation.");
            }

            _logger.LogInformation("Successfully provisioned tool '{ToolKey}' at '{ExecutablePath}' with verified SHA-256 hash ({Hash}).",
                toolKey, executablePath, installedHash);

            return new ProvisioningResult(toolKey, version, true, executablePath, null, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download or provision artifact for '{ToolKey}'.", toolKey);
            if (File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { }
            }
            if (File.Exists(executablePath))
            {
                try { File.Delete(executablePath); } catch { }
            }

            return new ProvisioningResult(toolKey, version, false, string.Empty, "DOWNLOAD_FAILED", $"Failed to download or provision artifact: {ex.Message}");
        }
    }

    private static async Task<Stream> DefaultDownloadArtifactStreamAsync(SecurityScanTool tool, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(tool.ArtifactUrl))
        {
            throw new InvalidOperationException($"Tool '{tool.ToolKey}' has no ArtifactUrl configured.");
        }

        using var client = new HttpClient();
        var response = await client.GetAsync(tool.ArtifactUrl, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStreamAsync(ct);
    }

    private static async Task<string> ComputeFileSha256Async(string filePath, CancellationToken ct)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hashBytes = await sha256.ComputeHashAsync(stream, ct);
        return Convert.ToHexStringLower(hashBytes);
    }
}
