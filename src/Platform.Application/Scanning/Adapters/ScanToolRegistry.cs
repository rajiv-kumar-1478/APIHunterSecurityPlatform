using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// Authoritative registry for scanner tool adapters.
/// Enforces fail-closed supply chain validation of all tool manifests at startup.
/// </summary>
public sealed class ScanToolRegistry : IScanToolRegistry
{
    private readonly Dictionary<string, IScanToolAdapter> _adapters;

    public ScanToolRegistry(IEnumerable<IScanToolAdapter> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);

        _adapters = new Dictionary<string, IScanToolAdapter>(StringComparer.OrdinalIgnoreCase);

        foreach (var adapter in adapters)
        {
            var manifest = adapter.Manifest;
            var validation = ScanToolManifestValidator.Validate(manifest);

            if (!validation.IsValid)
            {
                var joinedErrors = string.Join("; ", validation.Errors);
                throw new InvalidOperationException(
                    $"Scanner adapter '{manifest?.ToolKey ?? "unknown"}' failed manifest validation: {joinedErrors}");
            }

            if (_adapters.ContainsKey(manifest.ToolKey))
            {
                throw new InvalidOperationException(
                    $"Duplicate scanner adapter key registered: '{manifest.ToolKey}'.");
            }

            _adapters[manifest.ToolKey] = adapter;
        }
    }

    public IReadOnlyList<IScanToolAdapter> GetAllAdapters() => _adapters.Values.ToList();

    public IScanToolAdapter? GetAdapter(string toolKey)
    {
        if (string.IsNullOrWhiteSpace(toolKey)) return null;
        return _adapters.TryGetValue(toolKey, out var adapter) ? adapter : null;
    }

    public IReadOnlyList<IScanToolAdapter> GetAdaptersForProfile(SecurityScanProfileType profile)
    {
        return _adapters.Values
            .Where(a => a.Manifest.SupportedProfiles.Contains(profile))
            .ToList();
    }

    public IReadOnlyList<IScanToolAdapter> GetAdaptersForCapability(string capability)
    {
        if (string.IsNullOrWhiteSpace(capability)) return Array.Empty<IScanToolAdapter>();

        return _adapters.Values
            .Where(a => a.Manifest.Capabilities.Contains(capability))
            .ToList();
    }

    public IReadOnlyList<IScanToolAdapter> GetAdaptersForAssetType(string assetType)
    {
        if (string.IsNullOrWhiteSpace(assetType)) return Array.Empty<IScanToolAdapter>();

        return _adapters.Values
            .Where(a => a.Manifest.DiscoveredAssetTypes.Contains(assetType, StringComparer.OrdinalIgnoreCase))
            .ToList();
    }

    public Task<IReadOnlyList<ToolDiagnosticReport>> DiagnoseAllToolsAsync(CancellationToken ct = default)
    {
        var reports = new List<ToolDiagnosticReport>();

        foreach (var adapter in _adapters.Values)
        {
            var manifest = adapter.Manifest;
            var validation = ScanToolManifestValidator.Validate(manifest);

            var status = validation.IsValid ? ToolHealthStatus.Healthy : ToolHealthStatus.Degraded;
            var isValidDigest = !string.IsNullOrWhiteSpace(manifest.ContainerImageDigest) &&
                                manifest.ContainerImageDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
                                manifest.ContainerImageDigest.Length == 71;

            reports.Add(new ToolDiagnosticReport(
                ToolKey: manifest.ToolKey,
                Version: manifest.Version,
                Status: status,
                IsContainerImageDigestValid: isValidDigest,
                DeclaredCapabilities: manifest.Capabilities,
                ExecutionPhase: manifest.ExecutionPhase,
                LastDiagnosticAtUtc: DateTime.UtcNow,
                ErrorMessage: validation.IsValid ? null : string.Join("; ", validation.Errors)
            ));
        }

        return Task.FromResult<IReadOnlyList<ToolDiagnosticReport>>(reports.AsReadOnly());
    }
}
