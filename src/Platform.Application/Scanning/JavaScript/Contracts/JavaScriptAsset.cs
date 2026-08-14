using System;
using System.Collections.Generic;

namespace Platform.Application.Scanning.JavaScript.Contracts;

public enum JsAssetType
{
    JavaScript = 1,
    JavaScriptMap = 2,
    InlineScript = 3
}

/// <summary>
/// Immutable representation of a discovered JavaScript asset or source map.
/// </summary>
public sealed record JavaScriptAsset(
    Guid AssetId,
    Guid ScanJobId,
    string Url,
    string CanonicalUrl,
    JsAssetType AssetType,
    string ContentSha256,
    long ContentLengthBytes,
    int Depth,
    string? ParentAssetUrl = null,
    string? ContentType = null,
    string? SourceMapUrl = null,
    string? ContentArtifactReference = null,
    DateTime? DiscoveredAtUtc = null
);

/// <summary>
/// Configurable safety options and resource limits for the recursive JavaScript discovery crawler.
/// </summary>
public sealed record JsDiscoveryOptions(
    int MaxDepth = 3,
    int MaxFiles = 100,
    long MaxSingleFileBytes = 5 * 1024 * 1024,      // 5 MiB per file
    long MaxTotalCrawlBytes = 25 * 1024 * 1024,     // 25 MiB total crawl cap
    int TimeoutMs = 30_000,
    bool SameOriginOnly = true,
    IReadOnlySet<string>? AllowlistedExternalOrigins = null
);

/// <summary>
/// Historical change detection between two scan job JavaScript inventories.
/// </summary>
public sealed record JsAssetDiff(
    Guid CurrentScanJobId,
    Guid? BaselineScanJobId,
    IReadOnlyList<JavaScriptAsset> NewAssets,
    IReadOnlyList<JavaScriptAsset> ChangedAssets,
    IReadOnlyList<JavaScriptAsset> UnchangedAssets,
    IReadOnlyList<JavaScriptAsset> RemovedAssets,
    DateTime GeneratedAtUtc
);
