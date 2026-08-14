using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class JsDiscoveryEngineTests
{
    [Fact]
    public async Task DiscoverAssets_HtmlWithScriptsAndInline_ExtractsAllAssets()
    {
        var html = @"
<!DOCTYPE html>
<html>
<head>
    <script src=""/static/js/main.bundle.js""></script>
    <script>
        console.log('inline auth config');
    </script>
</head>
<body><h1>App</h1></body>
</html>";

        var mainJs = "console.log('main bundle');";

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("main.bundle.js"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(mainJs, Encoding.UTF8, "application/javascript")
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var client = new HttpClient(mockHandler);
        var engine = new JsDiscoveryEngine(client, NullLogger<JsDiscoveryEngine>.Instance);

        var assets = await engine.DiscoverAssetsAsync(
            scanJobId: Guid.NewGuid(),
            rootTargetUrl: "https://app.example.com/login",
            htmlContent: html
        );

        Assert.Equal(2, assets.Count);

        var externalAsset = assets.FirstOrDefault(a => a.AssetType == JsAssetType.JavaScript);
        Assert.NotNull(externalAsset);
        Assert.Equal("https://app.example.com/static/js/main.bundle.js", externalAsset.CanonicalUrl);
        Assert.Equal(0, externalAsset.Depth);

        var inlineAsset = assets.FirstOrDefault(a => a.AssetType == JsAssetType.InlineScript);
        Assert.NotNull(inlineAsset);
        Assert.StartsWith("https://app.example.com/login", inlineAsset.Url);
        Assert.Equal(0, inlineAsset.Depth);
    }

    [Fact]
    public async Task DiscoverAssets_DynamicImportsAndSourceMaps_RecursivelyDiscoversChildAssets()
    {
        var html = "<script src=\"/app.js\"></script>";
        var appJs = @"
import('./chunks/chunk-admin.js');
console.log('app code');
//# sourceMappingURL=app.js.map";
        var chunkAdminJs = "console.log('admin chunk');";
        var sourceMapJson = "{\"version\":3,\"file\":\"app.js\"}";

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/app.js")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(appJs, Encoding.UTF8, "application/javascript")
                };
            }
            if (path == "/chunks/chunk-admin.js")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(chunkAdminJs, Encoding.UTF8, "application/javascript")
                };
            }
            if (path == "/app.js.map")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(sourceMapJson, Encoding.UTF8, "application/json")
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var client = new HttpClient(mockHandler);
        var engine = new JsDiscoveryEngine(client, NullLogger<JsDiscoveryEngine>.Instance);

        var assets = await engine.DiscoverAssetsAsync(
            scanJobId: Guid.NewGuid(),
            rootTargetUrl: "https://app.example.com",
            htmlContent: html
        );

        Assert.Equal(3, assets.Count);

        var rootJs = assets.First(a => a.CanonicalUrl.EndsWith("/app.js"));
        Assert.Equal(0, rootJs.Depth);
        Assert.Equal("https://app.example.com/app.js.map", rootJs.SourceMapUrl);

        var chunkJs = assets.First(a => a.CanonicalUrl.EndsWith("/chunks/chunk-admin.js"));
        Assert.Equal(1, chunkJs.Depth);
        Assert.Equal(JsAssetType.JavaScript, chunkJs.AssetType);
        Assert.Equal("https://app.example.com/app.js", chunkJs.ParentAssetUrl);

        var mapAsset = assets.First(a => a.CanonicalUrl.EndsWith("/app.js.map"));
        Assert.Equal(1, mapAsset.Depth);
        Assert.Equal(JsAssetType.JavaScriptMap, mapAsset.AssetType);
    }

    [Fact]
    public async Task DiscoverAssets_DifferentUrlsWithIdenticalContent_MaintainsSeparateAssetIdentities()
    {
        var html = @"
<script src=""/app.js""></script>
<script src=""/vendor/app.js""></script>";

        var identicalJs = "console.log('identical library');";

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(identicalJs, Encoding.UTF8, "application/javascript")
            };
        });

        var client = new HttpClient(mockHandler);
        var engine = new JsDiscoveryEngine(client, NullLogger<JsDiscoveryEngine>.Instance);

        var assets = await engine.DiscoverAssetsAsync(
            scanJobId: Guid.NewGuid(),
            rootTargetUrl: "https://app.example.com",
            htmlContent: html
        );

        Assert.Equal(2, assets.Count);
        Assert.NotEqual(assets[0].CanonicalUrl, assets[1].CanonicalUrl);
        Assert.Equal(assets[0].ContentSha256, assets[1].ContentSha256);
    }

    [Fact]
    public async Task DiscoverAssets_CrossOriginFiltering_RespectsAllowlist()
    {
        var html = @"
<script src=""https://app.example.com/internal.js""></script>
<script src=""https://cdn.partner.com/trusted.js""></script>
<script src=""https://untrusted-tracker.com/track.js""></script>";

        var mockHandler = new MockHttpMessageHandler((req) =>
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("console.log('ok');", Encoding.UTF8, "application/javascript")
            };
        });

        var client = new HttpClient(mockHandler);
        var engine = new JsDiscoveryEngine(client, NullLogger<JsDiscoveryEngine>.Instance);

        var options = new JsDiscoveryOptions(
            SameOriginOnly: true,
            AllowlistedExternalOrigins: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "https://cdn.partner.com" }
        );

        var assets = await engine.DiscoverAssetsAsync(
            scanJobId: Guid.NewGuid(),
            rootTargetUrl: "https://app.example.com",
            htmlContent: html,
            options: options
        );

        Assert.Equal(2, assets.Count);
        Assert.Contains(assets, a => a.CanonicalUrl.Contains("internal.js"));
        Assert.Contains(assets, a => a.CanonicalUrl.Contains("trusted.js"));
        Assert.DoesNotContain(assets, a => a.CanonicalUrl.Contains("untrusted-tracker.com"));
    }

    [Fact]
    public void ComputeAssetDiff_DetectsNewChangedUnchangedAndRemovedAssets()
    {
        var scanJob1 = Guid.NewGuid();
        var scanJob2 = Guid.NewGuid();

        var assetUnchanged = new JavaScriptAsset(Guid.NewGuid(), scanJob1, "https://app.example.com/unchanged.js", "https://app.example.com/unchanged.js", JsAssetType.JavaScript, "sha_aaa", 100, 0);
        var assetChangedOld = new JavaScriptAsset(Guid.NewGuid(), scanJob1, "https://app.example.com/app.js", "https://app.example.com/app.js", JsAssetType.JavaScript, "sha_bbb_old", 200, 0);
        var assetRemoved = new JavaScriptAsset(Guid.NewGuid(), scanJob1, "https://app.example.com/deprecated.js", "https://app.example.com/deprecated.js", JsAssetType.JavaScript, "sha_ccc", 300, 0);

        var assetChangedNew = new JavaScriptAsset(Guid.NewGuid(), scanJob2, "https://app.example.com/app.js", "https://app.example.com/app.js", JsAssetType.JavaScript, "sha_bbb_new", 250, 0);
        var assetNew = new JavaScriptAsset(Guid.NewGuid(), scanJob2, "https://app.example.com/feature.js", "https://app.example.com/feature.js", JsAssetType.JavaScript, "sha_ddd", 150, 0);

        var baseline = new List<JavaScriptAsset> { assetUnchanged, assetChangedOld, assetRemoved };
        var current = new List<JavaScriptAsset> { assetUnchanged, assetChangedNew, assetNew };

        var engine = new JsDiscoveryEngine(new HttpClient(), NullLogger<JsDiscoveryEngine>.Instance);
        var diff = engine.ComputeAssetDiff(scanJob2, scanJob1, current, baseline);

        Assert.Single(diff.UnchangedAssets);
        Assert.Equal("https://app.example.com/unchanged.js", diff.UnchangedAssets[0].CanonicalUrl);

        Assert.Single(diff.ChangedAssets);
        Assert.Equal("https://app.example.com/app.js", diff.ChangedAssets[0].CanonicalUrl);
        Assert.Equal("sha_bbb_new", diff.ChangedAssets[0].ContentSha256);

        Assert.Single(diff.NewAssets);
        Assert.Equal("https://app.example.com/feature.js", diff.NewAssets[0].CanonicalUrl);

        Assert.Single(diff.RemovedAssets);
        Assert.Equal("https://app.example.com/deprecated.js", diff.RemovedAssets[0].CanonicalUrl);
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }
}
