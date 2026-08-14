using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative recursive JavaScript asset discovery engine.
/// Crawls web application HTML, inline scripts, dynamic chunk imports, and source maps with strict resource bounds.
/// Computes asset inventories and historical deployment diffs.
/// </summary>
public interface IJsDiscoveryEngine
{
    /// <summary>
    /// Recursively discovers and hashes all JavaScript assets and source maps exposed by the target.
    /// </summary>
    Task<IReadOnlyList<JavaScriptAsset>> DiscoverAssetsAsync(
        Guid scanJobId,
        string rootTargetUrl,
        string? htmlContent = null,
        JsDiscoveryOptions? options = null,
        CancellationToken ct = default);

    /// <summary>
    /// Computes historical changes (new, changed, unchanged, removed) between two scan asset inventories.
    /// </summary>
    JsAssetDiff ComputeAssetDiff(
        Guid currentScanJobId,
        Guid? baselineScanJobId,
        IReadOnlyList<JavaScriptAsset> currentAssets,
        IReadOnlyList<JavaScriptAsset> baselineAssets);
}
