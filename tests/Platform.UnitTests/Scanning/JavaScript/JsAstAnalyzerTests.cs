using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.JavaScript;

public class JsAstAnalyzerTests
{
    private readonly JsAstAnalyzer _analyzer;

    public JsAstAnalyzerTests()
    {
        _analyzer = new JsAstAnalyzer(NullLogger<JsAstAnalyzer>.Instance);
    }

    [Fact]
    public void AnalyzeAssets_FetchWithConstantFoldingAndTemplateLiteral_ExtractsAccurateEndpoint()
    {
        var jsCode = @"
const API_BASE = '/api/v2';
function getUser(userId) {
    return fetch(API_BASE + '/users/' + userId, {
        method: 'POST',
        headers: {
            'X-Tenant-Id': 'tenant-123'
        },
        body: JSON.stringify({
            name: 'Alice',
            role: 'Admin'
        })
    });
}";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/bundle.js",
            CanonicalUrl: "https://app.example.com/bundle.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_abc",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var graph = _analyzer.AnalyzeAssets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Equal(1, graph.TotalRoutesDiscovered);
        var endpoint = graph.Endpoints[0];

        Assert.Equal("POST", endpoint.HttpMethod);
        Assert.Equal("/api/v2/users/{userId}", endpoint.RoutePath);
        Assert.Equal(ApiEndpointProtocol.HttpRest, endpoint.Protocol);
        Assert.Equal(ResolutionQuality.ASTConstantFolded, endpoint.ResolutionQuality);
        Assert.Equal(FindingConfidence.High, endpoint.ASTConfidence);
        Assert.True(endpoint.Headers.ContainsKey("X-Tenant-Id"));

        Assert.Contains(endpoint.Parameters, p => p.Name == "userId" && p.Location == ParameterLocation.Path);
        Assert.Contains(endpoint.Parameters, p => p.Name == "name" && p.Location == ParameterLocation.Body);
        Assert.Contains(endpoint.Parameters, p => p.Name == "role" && p.Location == ParameterLocation.Body);
    }

    [Fact]
    public void AnalyzeAssets_AxiosOperations_ExtractsQueryAndBodyParameters()
    {
        var jsCode = @"
function search(q, limit) {
    axios.get('/api/search', {
        params: {
            q: q,
            limit: limit
        }
    });
}

function login(username, password) {
    axios.post('/api/auth/login', {
        username: username,
        password: password
    });
}";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/app.js",
            CanonicalUrl: "https://app.example.com/app.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_xyz",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var graph = _analyzer.AnalyzeAssets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Equal(2, graph.TotalRoutesDiscovered);

        var getSearch = graph.Endpoints.First(e => e.RoutePath == "/api/search");
        Assert.Equal("GET", getSearch.HttpMethod);
        Assert.Contains(getSearch.Parameters, p => p.Name == "q" && p.Location == ParameterLocation.Query);
        Assert.Contains(getSearch.Parameters, p => p.Name == "limit" && p.Location == ParameterLocation.Query);

        var postLogin = graph.Endpoints.First(e => e.RoutePath == "/api/auth/login");
        Assert.Equal("POST", postLogin.HttpMethod);
        Assert.Contains(postLogin.Parameters, p => p.Name == "username" && p.Location == ParameterLocation.Body);
        Assert.Contains(postLogin.Parameters, p => p.Name == "password" && p.Location == ParameterLocation.Body);
    }

    [Fact]
    public void AnalyzeAssets_XMLHttpRequest_ExtractsMethodAndRoute()
    {
        var jsCode = @"
const xhr = new XMLHttpRequest();
xhr.open('PUT', '/api/items/update');
xhr.send();";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/legacy.js",
            CanonicalUrl: "https://app.example.com/legacy.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_legacy",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var graph = _analyzer.AnalyzeAssets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Equal(1, graph.TotalRoutesDiscovered);
        var endpoint = graph.Endpoints[0];
        Assert.Equal("PUT", endpoint.HttpMethod);
        Assert.Equal("/api/items/update", endpoint.RoutePath);
    }

    [Fact]
    public void AnalyzeAssets_GraphQLOperations_ExtractsOperationDetails()
    {
        var jsCode = @"
const UPDATE_USER_MUTATION = gql`
mutation UpdateUserRole($userId: ID!, $newRole: String!) {
    updateUser(id: $userId, role: $newRole) {
        id
        name
        role
    }
}`;";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/graphql.js",
            CanonicalUrl: "https://app.example.com/graphql.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_gql",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var graph = _analyzer.AnalyzeAssets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Equal(1, graph.GraphQLOperationsCount);
        var endpoint = graph.Endpoints[0];

        Assert.Equal(ApiEndpointProtocol.GraphQL, endpoint.Protocol);
        Assert.Equal("UpdateUserRole", endpoint.OperationName);
        Assert.Equal("Mutation", endpoint.GraphQlOperationType);
        Assert.Contains(endpoint.Parameters, p => p.Name == "userId");
        Assert.Contains(endpoint.Parameters, p => p.Name == "newRole");
    }

    [Fact]
    public void AnalyzeAssets_WebSocketConstructor_ExtractsWebSocketEndpoint()
    {
        var jsCode = "const socket = new WebSocket('wss://stream.example.com/events');";

        var asset = new JavaScriptAsset(
            AssetId: Guid.NewGuid(),
            ScanJobId: Guid.NewGuid(),
            Url: "https://app.example.com/ws.js",
            CanonicalUrl: "https://app.example.com/ws.js",
            AssetType: JsAssetType.JavaScript,
            ContentSha256: "sha_ws",
            ContentLengthBytes: jsCode.Length,
            Depth: 0
        );

        var graph = _analyzer.AnalyzeAssets(asset.ScanJobId, new[] { (asset, jsCode) });

        Assert.Equal(1, graph.WebSocketEndpointsCount);
        var endpoint = graph.Endpoints[0];

        Assert.Equal(ApiEndpointProtocol.WebSocket, endpoint.Protocol);
        Assert.Equal("WS", endpoint.HttpMethod);
        Assert.Equal("/events", endpoint.RoutePath);
        Assert.Equal("wss://stream.example.com/events", endpoint.FullUrl);
    }

    [Fact]
    public void ComputeAttackSurfaceDiff_DetectsNewEndpointBetweenDeployments()
    {
        var job1 = Guid.NewGuid();
        var job2 = Guid.NewGuid();

        var ep1 = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "GET", "/api/users/{id}", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("id", ParameterLocation.Path) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 10, 5, ResolutionQuality.ASTTemplateResolvable, FindingConfidence.High);
        var ep2 = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "POST", "/api/admin/export", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("format", ParameterLocation.Query) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 25, 5, ResolutionQuality.ASTLiteral, FindingConfidence.High);

        var baselineGraph = new JsAttackSurfaceGraph(
            job1,
            new[] { ep1 },
            new Dictionary<string, IReadOnlyList<Guid>> { ["https://app.example.com/app.js"] = new[] { ep1.EndpointId } },
            1, 1, 0, 0, DateTime.UtcNow);

        var currentGraph = new JsAttackSurfaceGraph(
            job2,
            new[] { ep1, ep2 },
            new Dictionary<string, IReadOnlyList<Guid>> { ["https://app.example.com/app.js"] = new[] { ep1.EndpointId, ep2.EndpointId } },
            2, 2, 0, 0, DateTime.UtcNow);

        var diff = _analyzer.ComputeAttackSurfaceDiff(job2, job1, currentGraph, baselineGraph);

        Assert.Single(diff.UnchangedEndpoints);
        Assert.Equal("/api/users/{id}", diff.UnchangedEndpoints[0].RoutePath);

        Assert.Single(diff.NewEndpoints);
        Assert.Equal("POST", diff.NewEndpoints[0].HttpMethod);
        Assert.Equal("/api/admin/export", diff.NewEndpoints[0].RoutePath);
    }
}
