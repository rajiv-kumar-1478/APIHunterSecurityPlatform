using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// Central registry for discoverable, validated scanner tool adapters.
/// </summary>
public interface IScanToolRegistry
{
    /// <summary>Gets all registered tool adapters.</summary>
    IReadOnlyList<IScanToolAdapter> GetAllAdapters();

    /// <summary>Gets adapter by tool key, or null if not found.</summary>
    IScanToolAdapter? GetAdapter(string toolKey);

    /// <summary>Gets all adapters supporting a given scan profile.</summary>
    IReadOnlyList<IScanToolAdapter> GetAdaptersForProfile(SecurityScanProfileType profile);

    /// <summary>Gets all adapters declaring a given capability tag.</summary>
    IReadOnlyList<IScanToolAdapter> GetAdaptersForCapability(string capability);
}
