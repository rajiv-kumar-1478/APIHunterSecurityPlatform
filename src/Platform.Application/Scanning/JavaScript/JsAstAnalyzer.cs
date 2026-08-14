using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative ECMAScript AST analyzer for structural API, GraphQL, and WebSocket discovery.
/// Utilizes Acornima for AST parsing, applies bounded constant propagation, and normalizes attack-surface graphs.
/// </summary>
public sealed class JsAstAnalyzer : IJsAstAnalyzer
{
    private static readonly Regex GraphQlOpRegex = new(
        @"(?:query|mutation|subscription)\s+(?<name>[a-zA-Z0-9_]+)\s*(?:\((?<vars>[^\)]*)\))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex GraphQlFieldRegex = new(
        @"(?:query|mutation|subscription)?[^{]*\{\s*(?<fields>[a-zA-Z0-9_\s,]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly ILogger<JsAstAnalyzer> _logger;

    public JsAstAnalyzer(ILogger<JsAstAnalyzer> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public JsAttackSurfaceGraph AnalyzeAssets(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string JsCode)> assets)
    {
        if (assets == null || assets.Count == 0)
        {
            return new JsAttackSurfaceGraph(
                ScanJobId: scanJobId,
                Endpoints: Array.Empty<DiscoveredApiEndpoint>(),
                AssetToEndpointMap: new Dictionary<string, IReadOnlyList<Guid>>(),
                TotalRoutesDiscovered: 0,
                TotalParametersDiscovered: 0,
                GraphQLOperationsCount: 0,
                WebSocketEndpointsCount: 0,
                GeneratedAtUtc: DateTime.UtcNow
            );
        }

        var allEndpoints = new List<DiscoveredApiEndpoint>();
        var assetToEndpointMap = new Dictionary<string, List<Guid>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (asset, jsCode) in assets)
        {
            if (string.IsNullOrWhiteSpace(jsCode)) continue;

            try
            {
                var parser = new Parser(new ParserOptions
                {
                    Tolerant = true
                });

                Program? program = null;
                try
                {
                    program = parser.ParseScript(jsCode);
                }
                catch
                {
                    // Fallback to module parsing if script fails on import/export keywords
                    try
                    {
                        program = parser.ParseModule(jsCode);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "AST parsing failed for asset '{Url}'. Proceeding with empty AST.", asset.CanonicalUrl);
                    }
                }

                if (program == null) continue;

                var assetEndpoints = AnalyzeProgram(asset, program, jsCode);
                var endpointIds = new List<Guid>();

                foreach (var ep in assetEndpoints)
                {
                    allEndpoints.Add(ep);
                    endpointIds.Add(ep.EndpointId);
                }

                assetToEndpointMap[asset.CanonicalUrl] = endpointIds;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unexpected error during AST analysis for asset '{Url}'.", asset.CanonicalUrl);
            }
        }

        var totalParams = allEndpoints.Sum(e => e.Parameters.Count);
        var gqlCount = allEndpoints.Count(e => e.Protocol == ApiEndpointProtocol.GraphQL);
        var wsCount = allEndpoints.Count(e => e.Protocol == ApiEndpointProtocol.WebSocket);

        var finalAssetMap = assetToEndpointMap.ToDictionary(
            kv => kv.Key,
            kv => (IReadOnlyList<Guid>)kv.Value.AsReadOnly(),
            StringComparer.OrdinalIgnoreCase
        );

        return new JsAttackSurfaceGraph(
            ScanJobId: scanJobId,
            Endpoints: allEndpoints.AsReadOnly(),
            AssetToEndpointMap: finalAssetMap,
            TotalRoutesDiscovered: allEndpoints.Count,
            TotalParametersDiscovered: totalParams,
            GraphQLOperationsCount: gqlCount,
            WebSocketEndpointsCount: wsCount,
            GeneratedAtUtc: DateTime.UtcNow
        );
    }

    public JsAttackSurfaceDiff ComputeAttackSurfaceDiff(
        Guid currentScanJobId,
        Guid? baselineScanJobId,
        JsAttackSurfaceGraph currentGraph,
        JsAttackSurfaceGraph baselineGraph)
    {
        currentGraph ??= new JsAttackSurfaceGraph(currentScanJobId, Array.Empty<DiscoveredApiEndpoint>(), new Dictionary<string, IReadOnlyList<Guid>>(), 0, 0, 0, 0, DateTime.UtcNow);
        baselineGraph ??= new JsAttackSurfaceGraph(baselineScanJobId ?? Guid.Empty, Array.Empty<DiscoveredApiEndpoint>(), new Dictionary<string, IReadOnlyList<Guid>>(), 0, 0, 0, 0, DateTime.UtcNow);

        var baselineMap = baselineGraph.Endpoints.ToDictionary(e => $"{e.HttpMethod} {e.RoutePath}", StringComparer.OrdinalIgnoreCase);
        var currentMap = currentGraph.Endpoints.ToDictionary(e => $"{e.HttpMethod} {e.RoutePath}", StringComparer.OrdinalIgnoreCase);

        var newEndpoints = new List<DiscoveredApiEndpoint>();
        var changedEndpoints = new List<DiscoveredApiEndpoint>();
        var unchangedEndpoints = new List<DiscoveredApiEndpoint>();
        var removedEndpoints = new List<DiscoveredApiEndpoint>();

        foreach (var current in currentGraph.Endpoints)
        {
            var key = $"{current.HttpMethod} {current.RoutePath}";
            if (baselineMap.TryGetValue(key, out var baseline))
            {
                // Check if parameters or protocol changed
                bool paramsEqual = current.Parameters.Count == baseline.Parameters.Count &&
                                   current.Parameters.All(p => baseline.Parameters.Any(bp => bp.Name.Equals(p.Name, StringComparison.OrdinalIgnoreCase) && bp.Location == p.Location));

                if (paramsEqual && current.Protocol == baseline.Protocol)
                {
                    unchangedEndpoints.Add(current);
                }
                else
                {
                    changedEndpoints.Add(current);
                }
            }
            else
            {
                newEndpoints.Add(current);
            }
        }

        foreach (var baseline in baselineGraph.Endpoints)
        {
            var key = $"{baseline.HttpMethod} {baseline.RoutePath}";
            if (!currentMap.ContainsKey(key))
            {
                removedEndpoints.Add(baseline);
            }
        }

        return new JsAttackSurfaceDiff(
            CurrentScanJobId: currentScanJobId,
            BaselineScanJobId: baselineScanJobId,
            NewEndpoints: newEndpoints.AsReadOnly(),
            ChangedEndpoints: changedEndpoints.AsReadOnly(),
            UnchangedEndpoints: unchangedEndpoints.AsReadOnly(),
            RemovedEndpoints: removedEndpoints.AsReadOnly(),
            GeneratedAtUtc: DateTime.UtcNow
        );
    }

    private List<DiscoveredApiEndpoint> AnalyzeProgram(JavaScriptAsset asset, Program program, string fullCode)
    {
        var endpoints = new List<DiscoveredApiEndpoint>();
        var constantTable = new Dictionary<string, string>(StringComparer.Ordinal);

        // First pass: Build bounded constant table (e.g. const API = "/api/v2")
        foreach (var node in program.ChildNodes)
        {
            if (node is VariableDeclaration varDecl)
            {
                foreach (var declarator in varDecl.Declarations)
                {
                    if (declarator.Id is Identifier id && declarator.Init != null)
                    {
                        var constantVal = EvaluateConstantString(declarator.Init, constantTable);
                        if (!string.IsNullOrWhiteSpace(constantVal))
                        {
                            constantTable[id.Name] = constantVal;
                        }
                    }
                }
            }
        }

        // Second pass: Traverse AST nodes for API invocations
        foreach (var node in program.DescendantNodes())
        {
            // 1. CallExpression: fetch, axios, xhr, $.ajax, io
            if (node is CallExpression call)
            {
                ProcessCallExpression(asset, call, constantTable, endpoints, fullCode);
            }
            // 2. NewExpression: new WebSocket(url)
            else if (node is NewExpression newExpr)
            {
                ProcessNewExpression(asset, newExpr, constantTable, endpoints, fullCode);
            }
            // 3. TaggedTemplateExpression: gql`query ...`
            else if (node is TaggedTemplateExpression taggedTemplate)
            {
                ProcessTaggedTemplateExpression(asset, taggedTemplate, constantTable, endpoints, fullCode);
            }
        }

        return endpoints;
    }

    private void ProcessCallExpression(
        JavaScriptAsset asset,
        CallExpression call,
        Dictionary<string, string> constantTable,
        List<DiscoveredApiEndpoint> endpoints,
        string fullCode)
    {
        // 1. fetch(url, options)
        if (call.Callee is Identifier { Name: "fetch" } && call.Arguments.Count > 0)
        {
            var (routePath, quality, pathParams) = ResolveUrlExpression(call.Arguments[0], constantTable);
            if (string.IsNullOrWhiteSpace(routePath)) return;

            string method = "GET";
            var headers = new Dictionary<string, string>();
            var allParams = new List<DiscoveredParameter>(pathParams);

            if (call.Arguments.Count > 1 && call.Arguments[1] is ObjectExpression optionsObj)
            {
                ExtractFetchOptions(optionsObj, constantTable, ref method, headers, allParams);
            }

            var snippet = GetCodeSnippet(call, fullCode);
            var confidence = quality switch
            {
                ResolutionQuality.ASTLiteral => FindingConfidence.High,
                ResolutionQuality.ASTTemplateResolvable => FindingConfidence.High,
                ResolutionQuality.ASTConstantFolded => FindingConfidence.High,
                ResolutionQuality.ASTPartiallyResolved => FindingConfidence.Medium,
                _ => FindingConfidence.Low
            };

            endpoints.Add(new DiscoveredApiEndpoint(
                EndpointId: Guid.NewGuid(),
                SourceAssetUrl: asset.CanonicalUrl,
                HttpMethod: method.ToUpperInvariant(),
                RoutePath: NormalizeRoutePath(routePath),
                FullUrl: routePath.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? routePath : null,
                Protocol: ApiEndpointProtocol.HttpRest,
                Parameters: allParams.AsReadOnly(),
                Headers: headers,
                OperationName: null,
                GraphQlOperationType: null,
                GraphQlFields: null,
                CodeSnippet: snippet,
                LineNumber: call.Location.Start.Line,
                ColumnNumber: call.Location.Start.Column,
                ResolutionQuality: quality,
                ASTConfidence: confidence
            ));
        }
        // 2. axios.get/post/put/delete/patch(url, data, config) or axios(config)
        else if (call.Callee is MemberExpression { Object: Identifier { Name: "axios" }, Property: Identifier prop })
        {
            var method = prop.Name.ToUpperInvariant();
            if (new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" }.Contains(method) && call.Arguments.Count > 0)
            {
                var (routePath, quality, pathParams) = ResolveUrlExpression(call.Arguments[0], constantTable);
                if (string.IsNullOrWhiteSpace(routePath)) return;

                var headers = new Dictionary<string, string>();
                var allParams = new List<DiscoveredParameter>(pathParams);

                // For POST/PUT: 2nd arg is data, 3rd arg is config
                if (method is "POST" or "PUT" or "PATCH")
                {
                    if (call.Arguments.Count > 1 && call.Arguments[1] is ObjectExpression dataObj)
                    {
                        ExtractObjectParameters(dataObj, ParameterLocation.Body, allParams);
                    }
                    if (call.Arguments.Count > 2 && call.Arguments[2] is ObjectExpression configObj)
                    {
                        ExtractAxiosConfig(configObj, constantTable, headers, allParams);
                    }
                }
                else
                {
                    if (call.Arguments.Count > 1 && call.Arguments[1] is ObjectExpression configObj)
                    {
                        ExtractAxiosConfig(configObj, constantTable, headers, allParams);
                    }
                }

                var snippet = GetCodeSnippet(call, fullCode);
                var confidence = quality == ResolutionQuality.DynamicUnknown ? FindingConfidence.Low : FindingConfidence.High;

                endpoints.Add(new DiscoveredApiEndpoint(
                    EndpointId: Guid.NewGuid(),
                    SourceAssetUrl: asset.CanonicalUrl,
                    HttpMethod: method,
                    RoutePath: NormalizeRoutePath(routePath),
                    FullUrl: routePath.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? routePath : null,
                    Protocol: ApiEndpointProtocol.HttpRest,
                    Parameters: allParams.AsReadOnly(),
                    Headers: headers,
                    OperationName: null,
                    GraphQlOperationType: null,
                    GraphQlFields: null,
                    CodeSnippet: snippet,
                    LineNumber: call.Location.Start.Line,
                    ColumnNumber: call.Location.Start.Column,
                    ResolutionQuality: quality,
                    ASTConfidence: confidence
                ));
            }
        }
        // 3. xhr.open(method, url)
        else if (call.Callee is MemberExpression { Property: Identifier { Name: "open" } } && call.Arguments.Count >= 2)
        {
            var methodStr = EvaluateConstantString(call.Arguments[0], constantTable) ?? "GET";
            var (routePath, quality, pathParams) = ResolveUrlExpression(call.Arguments[1], constantTable);
            if (!string.IsNullOrWhiteSpace(routePath))
            {
                var snippet = GetCodeSnippet(call, fullCode);
                endpoints.Add(new DiscoveredApiEndpoint(
                    EndpointId: Guid.NewGuid(),
                    SourceAssetUrl: asset.CanonicalUrl,
                    HttpMethod: methodStr.ToUpperInvariant(),
                    RoutePath: NormalizeRoutePath(routePath),
                    FullUrl: routePath.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? routePath : null,
                    Protocol: ApiEndpointProtocol.HttpRest,
                    Parameters: pathParams.AsReadOnly(),
                    Headers: new Dictionary<string, string>(),
                    OperationName: null,
                    GraphQlOperationType: null,
                    GraphQlFields: null,
                    CodeSnippet: snippet,
                    LineNumber: call.Location.Start.Line,
                    ColumnNumber: call.Location.Start.Column,
                    ResolutionQuality: quality,
                    ASTConfidence: quality == ResolutionQuality.DynamicUnknown ? FindingConfidence.Low : FindingConfidence.High
                ));
            }
        }
    }

    private void ProcessNewExpression(
        JavaScriptAsset asset,
        NewExpression newExpr,
        Dictionary<string, string> constantTable,
        List<DiscoveredApiEndpoint> endpoints,
        string fullCode)
    {
        if (newExpr.Callee is Identifier { Name: "WebSocket" } && newExpr.Arguments.Count > 0)
        {
            var (wsUrl, quality, pathParams) = ResolveUrlExpression(newExpr.Arguments[0], constantTable);
            if (!string.IsNullOrWhiteSpace(wsUrl))
            {
                var snippet = GetCodeSnippet(newExpr, fullCode);
                endpoints.Add(new DiscoveredApiEndpoint(
                    EndpointId: Guid.NewGuid(),
                    SourceAssetUrl: asset.CanonicalUrl,
                    HttpMethod: "WS",
                    RoutePath: NormalizeRoutePath(wsUrl),
                    FullUrl: wsUrl.StartsWith("ws", StringComparison.OrdinalIgnoreCase) ? wsUrl : null,
                    Protocol: ApiEndpointProtocol.WebSocket,
                    Parameters: pathParams.AsReadOnly(),
                    Headers: new Dictionary<string, string>(),
                    OperationName: null,
                    GraphQlOperationType: null,
                    GraphQlFields: null,
                    CodeSnippet: snippet,
                    LineNumber: newExpr.Location.Start.Line,
                    ColumnNumber: newExpr.Location.Start.Column,
                    ResolutionQuality: quality,
                    ASTConfidence: FindingConfidence.High
                ));
            }
        }
    }

    private void ProcessTaggedTemplateExpression(
        JavaScriptAsset asset,
        TaggedTemplateExpression taggedTemplate,
        Dictionary<string, string> constantTable,
        List<DiscoveredApiEndpoint> endpoints,
        string fullCode)
    {
        var tagName = taggedTemplate.Tag switch
        {
            Identifier id => id.Name,
            MemberExpression mem when mem.Property is Identifier id => id.Name,
            _ => null
        };

        if (tagName is "gql" or "graphql")
        {
            var rawGqlText = string.Join(" ", taggedTemplate.Quasi.Quasis.Select(q => q.Value.Raw));
            if (string.IsNullOrWhiteSpace(rawGqlText)) return;

            var opMatch = GraphQlOpRegex.Match(rawGqlText);
            var opName = opMatch.Success ? opMatch.Groups["name"].Value : "AnonymousQuery";
            var opType = rawGqlText.TrimStart().StartsWith("mutation", StringComparison.OrdinalIgnoreCase) ? "Mutation" : "Query";

            var variables = new List<DiscoveredParameter>();
            if (opMatch.Success && opMatch.Groups["vars"].Success)
            {
                var varsRaw = opMatch.Groups["vars"].Value;
                foreach (var v in varsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var cleanVar = v.Trim().TrimStart('$').Split(':')[0].Trim();
                    if (!string.IsNullOrWhiteSpace(cleanVar))
                    {
                        variables.Add(new DiscoveredParameter(cleanVar, ParameterLocation.Body, "GraphQLVariable"));
                    }
                }
            }

            var fields = new List<string>();
            var fieldMatch = GraphQlFieldRegex.Match(rawGqlText);
            if (fieldMatch.Success)
            {
                fields.AddRange(fieldMatch.Groups["fields"].Value.Split(new[] { ' ', ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }

            var snippet = GetCodeSnippet(taggedTemplate, fullCode);

            endpoints.Add(new DiscoveredApiEndpoint(
                EndpointId: Guid.NewGuid(),
                SourceAssetUrl: asset.CanonicalUrl,
                HttpMethod: "POST",
                RoutePath: "/graphql",
                FullUrl: null,
                Protocol: ApiEndpointProtocol.GraphQL,
                Parameters: variables.AsReadOnly(),
                Headers: new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                OperationName: opName,
                GraphQlOperationType: opType,
                GraphQlFields: fields.AsReadOnly(),
                CodeSnippet: snippet,
                LineNumber: taggedTemplate.Location.Start.Line,
                ColumnNumber: taggedTemplate.Location.Start.Column,
                ResolutionQuality: ResolutionQuality.ASTLiteral,
                ASTConfidence: FindingConfidence.High
            ));
        }
    }

    private static (string? RoutePath, ResolutionQuality Quality, List<DiscoveredParameter> PathParams) ResolveUrlExpression(
        Expression expr,
        Dictionary<string, string> constantTable)
    {
        var pathParams = new List<DiscoveredParameter>();

        // 1. Literal string: "/api/users"
        if (expr is StringLiteral strLit)
        {
            return (strLit.Value, ResolutionQuality.ASTLiteral, pathParams);
        }

        // 2. Identifier: const API = "/api"
        if (expr is Identifier id && constantTable.TryGetValue(id.Name, out var val))
        {
            return (val, ResolutionQuality.ASTConstantFolded, pathParams);
        }

        // 3. TemplateLiteral: `/api/users/${userId}/export`
        if (expr is TemplateLiteral templateLit)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < templateLit.Quasis.Count; i++)
            {
                sb.Append(templateLit.Quasis[i].Value.Raw);
                if (i < templateLit.Expressions.Count)
                {
                    var paramName = GetExpressionName(templateLit.Expressions[i], constantTable);
                    sb.Append('{').Append(paramName).Append('}');
                    pathParams.Add(new DiscoveredParameter(paramName, ParameterLocation.Path));
                }
            }
            return (sb.ToString(), ResolutionQuality.ASTTemplateResolvable, pathParams);
        }

        // 4. BinaryExpression concatenation: API + "/users/" + id
        if (expr is BinaryExpression { Operator: Operator.Addition } binExpr)
        {
            var left = EvaluateConstantString(binExpr.Left, constantTable) ?? "{" + GetExpressionName(binExpr.Left, constantTable) + "}";
            var right = EvaluateConstantString(binExpr.Right, constantTable) ?? "{" + GetExpressionName(binExpr.Right, constantTable) + "}";

            if (left.StartsWith("{") && left.EndsWith("}")) pathParams.Add(new DiscoveredParameter(left.Trim('{', '}'), ParameterLocation.Path));
            if (right.StartsWith("{") && right.EndsWith("}")) pathParams.Add(new DiscoveredParameter(right.Trim('{', '}'), ParameterLocation.Path));

            var combined = left + right;
            return (combined, ResolutionQuality.ASTConstantFolded, pathParams);
        }

        return (null, ResolutionQuality.DynamicUnknown, pathParams);
    }

    private static string? EvaluateConstantString(Node? node, Dictionary<string, string> constantTable)
    {
        if (node is StringLiteral str) return str.Value;
        if (node is Identifier id && constantTable.TryGetValue(id.Name, out var v)) return v;
        if (node is BinaryExpression { Operator: Operator.Addition } bin)
        {
            var l = EvaluateConstantString(bin.Left, constantTable);
            var r = EvaluateConstantString(bin.Right, constantTable);
            if (l != null && r != null) return l + r;
        }
        return null;
    }

    private static string GetExpressionName(Expression expr, Dictionary<string, string> constantTable)
    {
        if (expr is Identifier id) return id.Name;
        if (expr is MemberExpression mem && mem.Property is Identifier pId) return pId.Name;
        return "param";
    }

    private static void ExtractFetchOptions(
        ObjectExpression options,
        Dictionary<string, string> constantTable,
        ref string method,
        Dictionary<string, string> headers,
        List<DiscoveredParameter> parameters)
    {
        foreach (var prop in options.Properties.OfType<Property>())
        {
            var propName = GetPropertyName(prop);
            if (propName.Equals("method", StringComparison.OrdinalIgnoreCase))
            {
                var m = EvaluateConstantString(prop.Value, constantTable);
                if (!string.IsNullOrWhiteSpace(m)) method = m.ToUpperInvariant();
            }
            else if (propName.Equals("headers", StringComparison.OrdinalIgnoreCase) && prop.Value is ObjectExpression headersObj)
            {
                foreach (var hProp in headersObj.Properties.OfType<Property>())
                {
                    var hKey = GetPropertyName(hProp);
                    var hVal = EvaluateConstantString(hProp.Value, constantTable) ?? "*";
                    headers[hKey] = hVal;
                }
            }
            else if (propName.Equals("body", StringComparison.OrdinalIgnoreCase))
            {
                if (prop.Value is ObjectExpression bodyObj)
                {
                    ExtractObjectParameters(bodyObj, ParameterLocation.Body, parameters);
                }
                else if (prop.Value is CallExpression bodyCall && bodyCall.Callee is MemberExpression { Object: Identifier { Name: "JSON" }, Property: Identifier { Name: "stringify" } } && bodyCall.Arguments.Count > 0 && bodyCall.Arguments[0] is ObjectExpression jsonBodyObj)
                {
                    ExtractObjectParameters(jsonBodyObj, ParameterLocation.Body, parameters);
                }
            }
        }
    }

    private static void ExtractAxiosConfig(
        ObjectExpression config,
        Dictionary<string, string> constantTable,
        Dictionary<string, string> headers,
        List<DiscoveredParameter> parameters)
    {
        foreach (var prop in config.Properties.OfType<Property>())
        {
            var propName = GetPropertyName(prop);
            if (propName.Equals("params", StringComparison.OrdinalIgnoreCase) && prop.Value is ObjectExpression paramsObj)
            {
                ExtractObjectParameters(paramsObj, ParameterLocation.Query, parameters);
            }
            else if (propName.Equals("headers", StringComparison.OrdinalIgnoreCase) && prop.Value is ObjectExpression headersObj)
            {
                foreach (var hProp in headersObj.Properties.OfType<Property>())
                {
                    var hKey = GetPropertyName(hProp);
                    var hVal = EvaluateConstantString(hProp.Value, constantTable) ?? "*";
                    headers[hKey] = hVal;
                }
            }
        }
    }

    private static void ExtractObjectParameters(ObjectExpression obj, ParameterLocation location, List<DiscoveredParameter> parameters)
    {
        foreach (var prop in obj.Properties.OfType<Property>())
        {
            var name = GetPropertyName(prop);
            if (!string.IsNullOrWhiteSpace(name) && !parameters.Any(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && p.Location == location))
            {
                parameters.Add(new DiscoveredParameter(name, location));
            }
        }
    }

    private static string GetPropertyName(Property prop)
    {
        if (prop.Key is Identifier id) return id.Name;
        if (prop.Key is StringLiteral str) return str.Value;
        return string.Empty;
    }

    private static string NormalizeRoutePath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "/";
        var trimmed = raw.Trim();
        if (trimmed.StartsWith("http://") || trimmed.StartsWith("https://") || trimmed.StartsWith("ws://") || trimmed.StartsWith("wss://"))
        {
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            {
                return uri.AbsolutePath;
            }
        }
        return trimmed.StartsWith('/') ? trimmed : "/" + trimmed;
    }

    private static string GetCodeSnippet(Node node, string fullCode)
    {
        if (string.IsNullOrWhiteSpace(fullCode)) return string.Empty;
        var start = Math.Clamp(node.Range.Start, 0, fullCode.Length);
        var length = Math.Clamp(node.Range.End - node.Range.Start, 0, Math.Min(512, fullCode.Length - start));
        return fullCode.Substring(start, length).Trim();
    }
}
