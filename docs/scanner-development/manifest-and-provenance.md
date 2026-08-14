# ScanToolManifest & Container Image Provenance

## Manifest Structure

The `ScanToolManifest` record declares the immutable software supply chain metadata for a scanner:

```csharp
public sealed record ScanToolManifest(
    string ToolKey,
    string Version,
    string Description,
    string ContainerImageRepository,
    string ContainerImageReference,
    string ContainerImageDigest,
    IReadOnlySet<SecurityScanProfileType> SupportedProfiles,
    IReadOnlySet<string> Capabilities,
    IReadOnlyList<string> DiscoveredAssetTypes,
    string ParserVersion,
    string ManifestVersion,
    ScannerExecutionPhase ExecutionPhase = ScannerExecutionPhase.Discovery,
    IReadOnlyList<string>? RequiredCapabilities = null
);
```

---

## Supply Chain Provenance Rules

1. **Authentic Registry Digests Only**:
   - `ContainerImageDigest` must be the cryptographic multi-arch manifest digest or platform-specific SHA-256 digest issued by the official OCI registry (e.g. `docker.io`, `ghcr.io`, `quay.io`).
   - Synthetic, placeholder, or truncated digests (e.g. `sha256:3b8c9d0e...`) are strictly forbidden.

2. **Immutable Version Pinning**:
   - `ContainerImageReference` must pin an exact version tag (e.g. `semgrep/semgrep:1.172.0` or `projectdiscovery/nuclei:v3.3.0`).
   - The `:latest` tag is prohibited.

3. **Fail-Closed Validation Gate**:
   - On application startup, `ScanToolRegistry` validates every manifest via `ScanToolManifestValidator.Validate(manifest)`.
   - If any manifest has invalid SemVer, invalid profile sets, empty capabilities, or malformed digests, the platform fails startup immediately.
