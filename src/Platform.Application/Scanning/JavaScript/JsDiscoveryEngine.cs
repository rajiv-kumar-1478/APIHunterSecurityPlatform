using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative recursive JavaScript asset discovery engine.
/// Extracts HTML scripts, inline blocks, dynamic chunk imports, and source maps with strict resource bounds.
/// Computes immutable asset inventories and deployment diffs.
/// </summary>
public sealed class JsDiscoveryEngine : IJsDiscoveryEngine
{
    private static readonly Regex ScriptTagRegex = new(
        @"<script\b(?<attrs>[^>]*)>(?<content>[\s\S]*?)<\/script>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SrcAttributeRegex = new(
        @"\bsrc\s*=\s*(?:""(?<src>[^""]*)""|'(?<src>[^']*)'|(?<src>[^\s>]+))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DynamicImportRegex = new(
        @"(?:import\s*\(\s*|require\.ensure\s*\(\s*\[?\s*|__webpack_require__\.e\s*\(\s*)['""](?<path>[^'""\)\s]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SourceMapRegex = new(
        @"//[#@]\s*sourceMappingURL\s*=\s*(?<url>[^\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HttpClient _httpClient;
    private readonly ILogger<JsDiscoveryEngine> _logger;

    public JsDiscoveryEngine(HttpClient httpClient, ILogger<JsDiscoveryEngine> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IReadOnlyList<JavaScriptAsset>> DiscoverAssetsAsync(
        Guid scanJobId,
        string rootTargetUrl,
        string? htmlContent = null,
        JsDiscoveryOptions? options = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rootTargetUrl))
        {
            throw new ArgumentException("Root target URL cannot be empty.", nameof(rootTargetUrl));
        }

        options ??= new JsDiscoveryOptions();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMilliseconds(options.TimeoutMs));
        var linkedToken = cts.Token;

        var baseUri = new Uri(rootTargetUrl);
        var discoveredAssets = new List<JavaScriptAsset>();
        var visitedCanonicalUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalCrawlBytes = 0;

        // Queue item: (Uri url, int depth, string? parentUrl, JsAssetType type, string? inlineContent)
        var queue = new Queue<(Uri Uri, int Depth, string? ParentUrl, JsAssetType Type, string? InlineContent)>();

        // 1. Initial HTML discovery phase
        if (string.IsNullOrWhiteSpace(htmlContent))
        {
            try
            {
                using var initialResponse = await _httpClient.GetAsync(baseUri, HttpCompletionOption.ResponseHeadersRead, linkedToken);
                if (initialResponse.IsSuccessStatusCode)
                {
                    var bytes = await initialResponse.Content.ReadAsByteArrayAsync(linkedToken);
                    htmlContent = Encoding.UTF8.GetString(bytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to fetch root HTML for target '{RootUrl}'. Proceeding with empty HTML.", rootTargetUrl);
                htmlContent = string.Empty;
            }
        }

        // Parse HTML for <script> tags
        if (!string.IsNullOrWhiteSpace(htmlContent))
        {
            ParseHtmlScripts(baseUri, htmlContent, queue);
        }

        // 2. Recursive crawl loop
        while (queue.Count > 0 && discoveredAssets.Count < options.MaxFiles && totalCrawlBytes < options.MaxTotalCrawlBytes)
        {
            linkedToken.ThrowIfCancellationRequested();

            var current = queue.Dequeue();
            var canonicalUrl = CanonicalizeUrl(current.Uri);

            if (visitedCanonicalUrls.Contains(canonicalUrl))
            {
                continue;
            }

            visitedCanonicalUrls.Add(canonicalUrl);

            // Scope Check: Same-origin or allowlisted external origins
            if (!IsOriginAllowed(current.Uri, baseUri, options))
            {
                _logger.LogDebug("Skipping out-of-scope JS asset: '{Url}'", current.Uri);
                continue;
            }

            if (current.Type == JsAssetType.InlineScript && current.InlineContent != null)
            {
                // Process inline script block
                var rawBytes = Encoding.UTF8.GetBytes(current.InlineContent);
                var sha256 = ComputeSha256(rawBytes);
                totalCrawlBytes += rawBytes.Length;

                var asset = new JavaScriptAsset(
                    AssetId: Guid.NewGuid(),
                    ScanJobId: scanJobId,
                    Url: current.Uri.ToString(),
                    CanonicalUrl: canonicalUrl,
                    AssetType: JsAssetType.InlineScript,
                    ContentSha256: sha256,
                    ContentLengthBytes: rawBytes.Length,
                    Depth: current.Depth,
                    ParentAssetUrl: current.ParentUrl,
                    ContentType: "text/javascript",
                    SourceMapUrl: null,
                    ContentArtifactReference: $"inline:{sha256[..12]}",
                    DiscoveredAtUtc: DateTime.UtcNow
                );

                discoveredAssets.Add(asset);

                // Check for dynamic imports inside inline JS
                if (current.Depth < options.MaxDepth)
                {
                    ExtractDynamicReferences(current.Uri, current.InlineContent, current.Depth, queue);
                }
            }
            else
            {
                // Fetch external JS or Source Map
                try
                {
                    using var response = await _httpClient.GetAsync(current.Uri, HttpCompletionOption.ResponseHeadersRead, linkedToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        continue;
                    }

                    var contentLength = response.Content.Headers.ContentLength ?? 0;
                    if (contentLength > options.MaxSingleFileBytes)
                    {
                        _logger.LogWarning("Skipping oversized JS file '{Url}' ({Size} bytes > {Max} bytes limit).",
                            current.Uri, contentLength, options.MaxSingleFileBytes);
                        continue;
                    }

                    var rawBytes = await response.Content.ReadAsByteArrayAsync(linkedToken);
                    if (rawBytes.Length > options.MaxSingleFileBytes)
                    {
                        continue;
                    }

                    var sha256 = ComputeSha256(rawBytes);
                    totalCrawlBytes += rawBytes.Length;
                    var contentText = Encoding.UTF8.GetString(rawBytes);

                    // Detect sourceMappingURL in JavaScript files
                    string? sourceMapUrl = null;
                    if (current.Type == JsAssetType.JavaScript)
                    {
                        var sourceMapMatch = SourceMapRegex.Match(contentText);
                        if (sourceMapMatch.Success)
                        {
                            var rawMapUrl = sourceMapMatch.Groups["url"].Value.Trim();
                            if (Uri.TryCreate(current.Uri, rawMapUrl, out var resolvedMapUri))
                            {
                                sourceMapUrl = resolvedMapUri.ToString();
                                if (current.Depth < options.MaxDepth)
                                {
                                    queue.Enqueue((resolvedMapUri, current.Depth + 1, current.Uri.ToString(), JsAssetType.JavaScriptMap, null));
                                }
                            }
                        }
                    }

                    var asset = new JavaScriptAsset(
                        AssetId: Guid.NewGuid(),
                        ScanJobId: scanJobId,
                        Url: current.Uri.ToString(),
                        CanonicalUrl: canonicalUrl,
                        AssetType: current.Type,
                        ContentSha256: sha256,
                        ContentLengthBytes: rawBytes.Length,
                        Depth: current.Depth,
                        ParentAssetUrl: current.ParentUrl,
                        ContentType: response.Content.Headers.ContentType?.MediaType ?? "application/javascript",
                        SourceMapUrl: sourceMapUrl,
                        ContentArtifactReference: $"blob:{sha256}",
                        DiscoveredAtUtc: DateTime.UtcNow
                    );

                    discoveredAssets.Add(asset);

                    // Extract dynamic chunk imports if within depth limit
                    if (current.Type == JsAssetType.JavaScript && current.Depth < options.MaxDepth)
                    {
                        ExtractDynamicReferences(current.Uri, contentText, current.Depth, queue);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to download JS asset '{Url}'.", current.Uri);
                }
            }
        }

        return discoveredAssets.AsReadOnly();
    }

    public JsAssetDiff ComputeAssetDiff(
        Guid currentScanJobId,
        Guid? baselineScanJobId,
        IReadOnlyList<JavaScriptAsset> currentAssets,
        IReadOnlyList<JavaScriptAsset> baselineAssets)
    {
        currentAssets ??= Array.Empty<JavaScriptAsset>();
        baselineAssets ??= Array.Empty<JavaScriptAsset>();

        var baselineMap = baselineAssets.ToDictionary(a => a.CanonicalUrl, StringComparer.OrdinalIgnoreCase);
        var currentMap = currentAssets.ToDictionary(a => a.CanonicalUrl, StringComparer.OrdinalIgnoreCase);

        var newAssets = new List<JavaScriptAsset>();
        var changedAssets = new List<JavaScriptAsset>();
        var unchangedAssets = new List<JavaScriptAsset>();
        var removedAssets = new List<JavaScriptAsset>();

        foreach (var current in currentAssets)
        {
            if (baselineMap.TryGetValue(current.CanonicalUrl, out var baseline))
            {
                if (string.Equals(current.ContentSha256, baseline.ContentSha256, StringComparison.OrdinalIgnoreCase))
                {
                    unchangedAssets.Add(current);
                }
                else
                {
                    changedAssets.Add(current);
                }
            }
            else
            {
                newAssets.Add(current);
            }
        }

        foreach (var baseline in baselineAssets)
        {
            if (!currentMap.ContainsKey(baseline.CanonicalUrl))
            {
                removedAssets.Add(baseline);
            }
        }

        return new JsAssetDiff(
            CurrentScanJobId: currentScanJobId,
            BaselineScanJobId: baselineScanJobId,
            NewAssets: newAssets.AsReadOnly(),
            ChangedAssets: changedAssets.AsReadOnly(),
            UnchangedAssets: unchangedAssets.AsReadOnly(),
            RemovedAssets: removedAssets.AsReadOnly(),
            GeneratedAtUtc: DateTime.UtcNow
        );
    }

    private static void ParseHtmlScripts(
        Uri baseUri,
        string htmlContent,
        Queue<(Uri Uri, int Depth, string? ParentUrl, JsAssetType Type, string? InlineContent)> queue)
    {
        var matches = ScriptTagRegex.Matches(htmlContent);
        int inlineCounter = 0;

        foreach (Match match in matches)
        {
            var attrs = match.Groups["attrs"].Value;
            var content = match.Groups["content"].Value.Trim();

            var srcMatch = SrcAttributeRegex.Match(attrs);
            if (srcMatch.Success)
            {
                var rawSrc = srcMatch.Groups["src"].Value.Trim();
                if (Uri.TryCreate(baseUri, rawSrc, out var resolvedUri))
                {
                    queue.Enqueue((resolvedUri, Depth: 0, ParentUrl: baseUri.ToString(), JsAssetType.JavaScript, InlineContent: null));
                }
            }
            else if (!string.IsNullOrWhiteSpace(content))
            {
                // Inline script block
                inlineCounter++;
                var virtualInlineUri = new Uri($"{baseUri}#inline-script-{inlineCounter}");
                queue.Enqueue((virtualInlineUri, Depth: 0, ParentUrl: baseUri.ToString(), JsAssetType.InlineScript, InlineContent: content));
            }
        }
    }

    private static void ExtractDynamicReferences(
        Uri parentUri,
        string jsContent,
        int currentDepth,
        Queue<(Uri Uri, int Depth, string? ParentUrl, JsAssetType Type, string? InlineContent)> queue)
    {
        var matches = DynamicImportRegex.Matches(jsContent);
        foreach (Match match in matches)
        {
            var rawPath = match.Groups["path"].Value.Trim();
            if (string.IsNullOrWhiteSpace(rawPath)) continue;

            // Normalize relative script paths (e.g. "./chunks/chunk-1.js" or "static/js/app.js")
            if (Uri.TryCreate(parentUri, rawPath, out var resolvedUri))
            {
                // Ensure extension looks like javascript or chunk
                if (resolvedUri.AbsolutePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                    resolvedUri.AbsolutePath.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase) ||
                    !Path.HasExtension(resolvedUri.AbsolutePath))
                {
                    queue.Enqueue((resolvedUri, currentDepth + 1, parentUri.ToString(), JsAssetType.JavaScript, null));
                }
            }
        }
    }

    private static bool IsOriginAllowed(Uri targetUri, Uri rootUri, JsDiscoveryOptions options)
    {
        if (!options.SameOriginOnly) return true;

        if (string.Equals(targetUri.Host, rootUri.Host, StringComparison.OrdinalIgnoreCase) &&
            targetUri.Port == rootUri.Port &&
            string.Equals(targetUri.Scheme, rootUri.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (options.AllowlistedExternalOrigins != null)
        {
            var origin = $"{targetUri.Scheme}://{targetUri.Authority}".ToLowerInvariant();
            if (options.AllowlistedExternalOrigins.Contains(origin) ||
                options.AllowlistedExternalOrigins.Contains(targetUri.Host.ToLowerInvariant()))
            {
                return true;
            }
        }

        return false;
    }

    public static string CanonicalizeUrl(Uri uri)
    {
        var builder = new UriBuilder(uri)
        {
            Fragment = string.Empty
        };

        if ((builder.Scheme == "http" && builder.Port == 80) ||
            (builder.Scheme == "https" && builder.Port == 443))
        {
            builder.Port = -1;
        }

        return builder.Uri.ToString().TrimEnd('/');
    }

    private static string ComputeSha256(byte[] data)
    {
        return Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    }
}
