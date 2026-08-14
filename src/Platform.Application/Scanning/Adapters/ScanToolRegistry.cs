using System;
using System.Collections.Generic;
using System.Linq;
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
}
