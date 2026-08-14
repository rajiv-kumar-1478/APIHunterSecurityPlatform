using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Planning.Contracts;
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

    /// <summary>Gets all adapters discovering a given asset type.</summary>
    IReadOnlyList<IScanToolAdapter> GetAdaptersForAssetType(string assetType);

    /// <summary>Runs non-intrusive diagnostic and provenance checks across all registered scanner adapters.</summary>
    Task<IReadOnlyList<ToolDiagnosticReport>> DiagnoseAllToolsAsync(CancellationToken ct = default);
}
