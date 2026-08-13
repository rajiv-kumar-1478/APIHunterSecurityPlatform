using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
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
    private const int MaxRedirectHops = 5;
    private const int MaxZipFileCount = 1000;
    private const long MaxUncompressedZipSizeBytes = 500 * 1024 * 1024; // 500 MB limit

    private readonly string _toolsRoot;
    private readonly IEgressPolicyEngine _egressPolicyEngine;
    private readonly Func<SecurityScanTool, CancellationToken, Task<Stream>>? _customArtifactDownloader;
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

    public static readonly HashSet<string> AllowedArtifactDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "github-releases.githubusercontent.com",
        "raw.githubusercontent.com",
        "s3.amazonaws.com",
        "apihunter.io"
    };

    public ToolProvisioningService(
        ILogger<ToolProvisioningService> logger,
        IEgressPolicyEngine egressPolicyEngine,
        string? toolsRoot = null,
        Func<SecurityScanTool, CancellationToken, Task<Stream>>? artifactDownloader = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _egressPolicyEngine = egressPolicyEngine ?? throw new ArgumentNullException(nameof(egressPolicyEngine));
        _toolsRoot = toolsRoot ?? Path.Combine(Path.GetTempPath(), "apihunter_tools");
        _customArtifactDownloader = artifactDownloader;
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

        // 4. Validate ArtifactUrl Host, Repository Identity Binding, & Egress Policy SSRF Protection
        if (!string.IsNullOrWhiteSpace(tool.ArtifactUrl))
        {
            if (!Uri.TryCreate(tool.ArtifactUrl, UriKind.Absolute, out var artifactUri))
            {
                return new ProvisioningResult(toolKey, version, false, string.Empty, "INVALID_ARTIFACT_URL", $"ArtifactUrl '{tool.ArtifactUrl}' is invalid.");
            }

            // Require HTTPS scheme for remote artifact URLs
            if (artifactUri.Scheme != Uri.UriSchemeHttps)
            {
                return new ProvisioningResult(toolKey, version, false, string.Empty, "NON_HTTPS_ARTIFACT_URL", "Artifact URL must use HTTPS.");
            }

            // Domain Allowlist Check
            var host = artifactUri.Host;
            var isDomainAllowed = AllowedArtifactDomains.Contains(host) || AllowedArtifactDomains.Any(domain => host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
            if (!isDomainAllowed)
            {
                _logger.LogError("Tool '{ToolKey}' ArtifactUrl host '{Host}' is not in untrusted artifact domain allowlist.", toolKey, host);
                return new ProvisioningResult(toolKey, version, false, string.Empty, "UNTRUSTED_ARTIFACT_URL_DOMAIN", $"Artifact URL host '{host}' is prohibited.");
            }

            // Bind ArtifactRepository to ArtifactUrl Path for github-release sources
            if (string.Equals(tool.ArtifactSourceType, "github-release", StringComparison.OrdinalIgnoreCase))
            {
                var expectedPathSegment = $"/{tool.ArtifactRepository.Trim().ToLowerInvariant()}/";
                if (!artifactUri.AbsolutePath.ToLowerInvariant().StartsWith(expectedPathSegment))
                {
                    _logger.LogError("Tool '{ToolKey}' ArtifactUrl path '{Path}' does not match registered ArtifactRepository '{Repo}'.", toolKey, artifactUri.AbsolutePath, tool.ArtifactRepository);
                    return new ProvisioningResult(toolKey, version, false, string.Empty, "REPOSITORY_URL_MISMATCH", $"ArtifactUrl does not match registered repository '{tool.ArtifactRepository}'.");
                }
            }

            // Egress Policy SSRF Verification (reject private/metadata IP targets)
            try
            {
                await _egressPolicyEngine.EvaluateAndBuildTargetAsync(tool.ArtifactUrl, TimeSpan.FromMinutes(5), ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Tool '{ToolKey}' ArtifactUrl '{Url}' failed SSRF egress validation.", toolKey, tool.ArtifactUrl);
                return new ProvisioningResult(toolKey, version, false, string.Empty, "ARTIFACT_URL_PROHIBITED_SSRF", $"Artifact URL egress validation failed: {ex.Message}");
            }
        }

        // 5. Construct Target Installation Directory
        var toolDir = Path.Combine(_toolsRoot, toolKey, version);
        Directory.CreateDirectory(toolDir);

        var executablePath = Path.Combine(toolDir, tool.Executable);

        // 6. Check if binary already exists locally with matching SHA-256
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

        // 7. Download Artifact Stream & Validate Redirects
        var tempFile = Path.Combine(toolDir, $"{toolKey}_{version}_{Guid.NewGuid():N}.tmp");
        try
        {
            _logger.LogInformation("Downloading artifact stream for '{ToolKey}'...", toolKey);
            await using (var artifactStream = _customArtifactDownloader != null
                ? await _customArtifactDownloader(tool, ct)
                : await DownloadArtifactStreamWithRedirectValidationAsync(tool, ct))
            {
                if (artifactStream == null)
                {
                    throw new InvalidOperationException("Artifact stream provider returned null stream.");
                }

                await using var fileStream = File.Create(tempFile);
                await artifactStream.CopyToAsync(fileStream, ct);
            }

            // 8. Verify Downloaded Artifact SHA-256 Stream Hash
            var downloadedHash = await ComputeFileSha256Async(tempFile, ct);
            if (!string.Equals(downloadedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Checksum Mismatch for '{ToolKey}': Expected '{Expected}', calculated '{Calculated}'. Installation aborted.",
                    toolKey, expectedHash, downloadedHash);

                File.Delete(tempFile);
                return new ProvisioningResult(toolKey, version, false, string.Empty, "CHECKSUM_MISMATCH", $"Downloaded artifact SHA-256 '{downloadedHash}' does not match expected '{expectedHash}'.");
            }

            // 9. Handle ArtifactFormat Extraction & Hardened ZIP Protections
            var format = tool.ArtifactFormat?.Trim().ToLowerInvariant() ?? "binary";
            if (format == "zip")
            {
                _logger.LogInformation("Extracting zip archive for '{ToolKey}' with hardened safety guards...", toolKey);
                var canonicalRootDir = Path.GetFullPath(toolDir);
                if (!canonicalRootDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
                {
                    canonicalRootDir += Path.DirectorySeparatorChar;
                }

                var seenEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                long totalUncompressedBytes = 0;
                int totalFileCount = 0;

                using (var archiveStream = File.OpenRead(tempFile))
                using (var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read))
                {
                    foreach (var entry in archive.Entries)
                    {
                        totalFileCount++;
                        if (totalFileCount > MaxZipFileCount)
                        {
                            archiveStream.Close();
                            File.Delete(tempFile);
                            return new ProvisioningResult(toolKey, version, false, string.Empty, "ZIP_FILE_COUNT_EXCEEDED", $"ZIP archive exceeds maximum file count limit of {MaxZipFileCount}.");
                        }

                        // Duplicate Entry Check
                        var normalizedEntryName = entry.FullName.Trim().ToLowerInvariant();
                        if (!seenEntries.Add(normalizedEntryName))
                        {
                            archiveStream.Close();
                            File.Delete(tempFile);
                            return new ProvisioningResult(toolKey, version, false, string.Empty, "DUPLICATE_ZIP_ENTRY", $"Duplicate entry path '{entry.FullName}' detected in ZIP archive.");
                        }

                        // Decompression Bomb Check
                        totalUncompressedBytes += entry.Length;
                        if (totalUncompressedBytes > MaxUncompressedZipSizeBytes)
                        {
                            archiveStream.Close();
                            File.Delete(tempFile);
                            return new ProvisioningResult(toolKey, version, false, string.Empty, "ZIP_DECOMPRESSION_BOMB_EXCEEDED", $"Total uncompressed size exceeds limit of {MaxUncompressedZipSizeBytes} bytes.");
                        }

                        // Canonical Extraction-Root Path Validation (Zip Slip Protection)
                        var destinationPath = Path.GetFullPath(Path.Combine(canonicalRootDir, entry.FullName));
                        if (!destinationPath.StartsWith(canonicalRootDir, StringComparison.OrdinalIgnoreCase))
                        {
                            archiveStream.Close();
                            File.Delete(tempFile);
                            return new ProvisioningResult(toolKey, version, false, string.Empty, "ZIP_SLIP_VULNERABILITY_DETECTED", "Archive entry path escapes extraction root directory.");
                        }

                        // Symlink / Reparse Point Attribute Verification
                        const int unixSymlinkFlag = 0xA000;
                        if ((entry.ExternalAttributes & (unixSymlinkFlag << 16)) != 0)
                        {
                            archiveStream.Close();
                            File.Delete(tempFile);
                            return new ProvisioningResult(toolKey, version, false, string.Empty, "ZIP_SYMLINK_PROHIBITED", "Symlinks are prohibited inside tool archives.");
                        }
                    }

                    var targetEntry = archive.Entries.FirstOrDefault(e => string.Equals(e.Name, tool.Executable, StringComparison.OrdinalIgnoreCase));
                    if (targetEntry == null)
                    {
                        archiveStream.Close();
                        File.Delete(tempFile);
                        return new ProvisioningResult(toolKey, version, false, string.Empty, "EXECUTABLE_NOT_FOUND_IN_ARCHIVE", $"Executable '{tool.Executable}' was not found inside zip archive.");
                    }

                    if (File.Exists(executablePath)) File.Delete(executablePath);
                    targetEntry.ExtractToFile(executablePath, overwrite: true);
                }

                File.Delete(tempFile);
            }
            else
            {
                // Binary format atomic move
                if (File.Exists(executablePath)) File.Delete(executablePath);
                File.Move(tempFile, executablePath);
            }

            var installedHash = await ComputeFileSha256Async(executablePath, ct);
            _logger.LogInformation("Successfully provisioned tool '{ToolKey}' at '{ExecutablePath}' (verified hash: {Hash}).", toolKey, executablePath, installedHash);

            return new ProvisioningResult(toolKey, version, true, executablePath, null, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download or provision artifact for '{ToolKey}'.", toolKey);
            if (File.Exists(tempFile)) { try { File.Delete(tempFile); } catch { } }
            if (File.Exists(executablePath)) { try { File.Delete(executablePath); } catch { } }

            return new ProvisioningResult(toolKey, version, false, string.Empty, "DOWNLOAD_FAILED", $"Failed to download or provision artifact: {ex.Message}");
        }
    }

    private async Task<Stream> DownloadArtifactStreamWithRedirectValidationAsync(SecurityScanTool tool, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(tool.ArtifactUrl))
        {
            throw new InvalidOperationException($"Tool '{tool.ToolKey}' has no ArtifactUrl configured.");
        }

        var currentUrl = tool.ArtifactUrl;
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler);

        for (var hop = 0; hop < MaxRedirectHops; hop++)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, currentUrl);
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if ((int)response.StatusCode >= 300 && (int)response.StatusCode <= 399)
            {
                var redirectLocation = response.Headers.Location;
                if (redirectLocation == null)
                {
                    throw new InvalidOperationException($"Redirect response missing Location header from '{currentUrl}'.");
                }

                var nextUri = redirectLocation.IsAbsoluteUri ? redirectLocation : new Uri(new Uri(currentUrl), redirectLocation);

                // 1. Require HTTPS for redirect targets
                if (nextUri.Scheme != Uri.UriSchemeHttps)
                {
                    throw new InvalidOperationException($"Redirect target '{nextUri}' is prohibited: Non-HTTPS scheme.");
                }

                // 2. Validate redirect host against domain allowlist
                var nextHost = nextUri.Host;
                var isAllowed = AllowedArtifactDomains.Contains(nextHost) || AllowedArtifactDomains.Any(domain => nextHost.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
                if (!isAllowed)
                {
                    throw new InvalidOperationException($"Redirect target host '{nextHost}' is untrusted.");
                }

                // 3. Re-evaluate SSRF Egress Policy for redirect URL
                await _egressPolicyEngine.EvaluateAndBuildTargetAsync(nextUri.ToString(), TimeSpan.FromMinutes(5), ct);

                currentUrl = nextUri.ToString();
                continue;
            }

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStreamAsync(ct);
        }

        throw new InvalidOperationException($"Download exceeded maximum allowed redirect limit of {MaxRedirectHops} hops.");
    }

    private static async Task<string> ComputeFileSha256Async(string filePath, CancellationToken ct)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hashBytes = await sha256.ComputeHashAsync(stream, ct);
        return Convert.ToHexStringLower(hashBytes);
    }
}
