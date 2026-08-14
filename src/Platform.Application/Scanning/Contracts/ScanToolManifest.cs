using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Immutable, code-controlled software supply chain manifest for a security scanner tool.
/// </summary>
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
    Platform.Application.Scanning.Planning.Contracts.ScannerExecutionPhase ExecutionPhase = Platform.Application.Scanning.Planning.Contracts.ScannerExecutionPhase.Discovery,
    IReadOnlyList<string>? RequiredCapabilities = null
);
