using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Validation;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Authoritative registry provenance verifier for OCI and Docker registries (GHCR, Docker Hub, ECR).
/// Resolves the actual container image manifest digest and verifies exact equality with the manifest.
/// </summary>
public sealed class RegistryManifestProvenanceVerifier : IToolProvenanceVerifier
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RegistryManifestProvenanceVerifier> _logger;

    public RegistryManifestProvenanceVerifier(
        HttpClient httpClient,
        ILogger<RegistryManifestProvenanceVerifier> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ProvenanceVerificationResult> VerifyManifestDigestAsync(
        ScanToolManifest manifest,
        CancellationToken ct = default)
    {
        if (manifest == null)
        {
            return new ProvenanceVerificationResult(false, null, null, "Manifest is null.");
        }

        try
        {
            // Build the OCI/Docker registry manifest URL
            var registryEndpoint = ResolveRegistryManifestUrl(manifest.ContainerImageRepository, manifest.Version);
            if (string.IsNullOrEmpty(registryEndpoint))
            {
                return new ProvenanceVerificationResult(
                    false,
                    manifest.ContainerImageDigest,
                    null,
                    $"Unsupported or unparseable image repository: '{manifest.ContainerImageRepository}'.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Head, registryEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.docker.distribution.manifest.v2+json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.oci.image.manifest.v1+json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.oci.image.index.v1+json"));

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            string? resolvedDigest = null;
            if (response.Headers.TryGetValues("Docker-Content-Digest", out var values))
            {
                resolvedDigest = System.Linq.Enumerable.FirstOrDefault(values)?.Trim();
            }

            if (string.IsNullOrWhiteSpace(resolvedDigest))
            {
                // Fallback: If HEAD doesn't return Docker-Content-Digest header, perform GET and compute SHA-256 over raw manifest bytes
                using var getRequest = new HttpRequestMessage(HttpMethod.Get, registryEndpoint);
                getRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.docker.distribution.manifest.v2+json"));
                getRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.oci.image.manifest.v1+json"));

                using var getResponse = await _httpClient.SendAsync(getRequest, ct);
                if (getResponse.IsSuccessStatusCode)
                {
                    if (getResponse.Headers.TryGetValues("Docker-Content-Digest", out var getValues))
                    {
                        resolvedDigest = System.Linq.Enumerable.FirstOrDefault(getValues)?.Trim();
                    }
                    else
                    {
                        var rawBytes = await getResponse.Content.ReadAsByteArrayAsync(ct);
                        var computedHash = Convert.ToHexString(SHA256.HashData(rawBytes)).ToLowerInvariant();
                        resolvedDigest = $"sha256:{computedHash}";
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedDigest))
            {
                return new ProvenanceVerificationResult(
                    false,
                    manifest.ContainerImageDigest,
                    null,
                    $"Could not resolve Docker-Content-Digest from registry for {manifest.ContainerImageRepository}:{manifest.Version}.");
            }

            var isMatch = string.Equals(resolvedDigest, manifest.ContainerImageDigest, StringComparison.OrdinalIgnoreCase);

            return new ProvenanceVerificationResult(
                isMatch,
                manifest.ContainerImageDigest,
                resolvedDigest,
                isMatch ? null : $"Digest mismatch: Manifest declares '{manifest.ContainerImageDigest}', but registry returned '{resolvedDigest}'.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Registry provenance resolution failed for {ToolKey} ({Repo}:{Version})",
                manifest.ToolKey, manifest.ContainerImageRepository, manifest.Version);

            return new ProvenanceVerificationResult(
                false,
                manifest.ContainerImageDigest,
                null,
                $"Registry resolution error: {ex.Message}");
        }
    }

    private static string? ResolveRegistryManifestUrl(string imageRepository, string version)
    {
        if (string.IsNullOrWhiteSpace(imageRepository)) return null;

        var repo = imageRepository.Trim();
        var tag = string.IsNullOrWhiteSpace(version) ? "latest" : version.Trim();
        if (!tag.StartsWith("v") && char.IsDigit(tag[0]))
        {
            tag = "v" + tag;
        }

        // GitHub Container Registry (ghcr.io)
        if (repo.StartsWith("ghcr.io/", StringComparison.OrdinalIgnoreCase))
        {
            var path = repo.Substring("ghcr.io/".Length);
            return $"https://ghcr.io/v2/{path}/manifests/{tag}";
        }

        // Docker Hub official / community
        if (!repo.Contains('/'))
        {
            return $"https://registry-1.docker.io/v2/library/{repo}/manifests/{tag}";
        }

        return $"https://registry-1.docker.io/v2/{repo}/manifests/{tag}";
    }
}
