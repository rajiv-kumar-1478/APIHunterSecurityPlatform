using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript.Contracts;

public enum ApiEndpointProtocol
{
    HttpRest = 1,
    GraphQL = 2,
    WebSocket = 3,
    GrpcWeb = 4
}

public enum ParameterLocation
{
    Query = 1,
    Path = 2,
    Body = 3,
    Header = 4
}

public enum ResolutionQuality
{
    /// <summary>Exact static string literal in AST (e.g. "/api/v1/login").</summary>
    ASTLiteral = 1,
    /// <summary>Template literal with resolvable variable placeholders (e.g. `/api/users/${id}`).</summary>
    ASTTemplateResolvable = 2,
    /// <summary>Constant evaluated via static constant propagation table (e.g. API_PREFIX + "/export").</summary>
    ASTConstantFolded = 3,
    /// <summary>Partially resolved with some dynamic expressions remaining.</summary>
    ASTPartiallyResolved = 4,
    /// <summary>Dynamic or unresolvable function call.</summary>
    DynamicUnknown = 5
}

/// <summary>
/// Parameter extracted from client-side AST invocation.
/// </summary>
public sealed record DiscoveredParameter(
    string Name,
    ParameterLocation Location,
    string? InferredType = null,
    bool IsRequired = false,
    string? DefaultValue = null
);

/// <summary>
/// Structural API, GraphQL, or WebSocket endpoint discovered via AST syntactic analysis.
/// </summary>
public sealed record DiscoveredApiEndpoint(
    Guid EndpointId,
    string SourceAssetUrl,
    string HttpMethod,
    string RoutePath,
    string? FullUrl,
    ApiEndpointProtocol Protocol,
    IReadOnlyList<DiscoveredParameter> Parameters,
    IReadOnlyDictionary<string, string> Headers,
    string? OperationName,
    string? GraphQlOperationType,
    IReadOnlyList<string>? GraphQlFields,
    string CodeSnippet,
    int LineNumber,
    int ColumnNumber,
    ResolutionQuality ResolutionQuality,
    FindingConfidence ASTConfidence
);

/// <summary>
/// Hierarchical Attack Surface Graph linking JavaScript assets to their discovered endpoints and parameters.
/// </summary>
public sealed record JsAttackSurfaceGraph(
    Guid ScanJobId,
    IReadOnlyList<DiscoveredApiEndpoint> Endpoints,
    IReadOnlyDictionary<string, IReadOnlyList<Guid>> AssetToEndpointMap,
    int TotalRoutesDiscovered,
    int TotalParametersDiscovered,
    int GraphQLOperationsCount,
    int WebSocketEndpointsCount,
    DateTime GeneratedAtUtc
);

/// <summary>
/// Incremental endpoint diff across deployments or scans to trigger targeted testing for newly introduced APIs.
/// </summary>
public sealed record JsAttackSurfaceDiff(
    Guid CurrentScanJobId,
    Guid? BaselineScanJobId,
    IReadOnlyList<DiscoveredApiEndpoint> NewEndpoints,
    IReadOnlyList<DiscoveredApiEndpoint> ChangedEndpoints,
    IReadOnlyList<DiscoveredApiEndpoint> UnchangedEndpoints,
    IReadOnlyList<DiscoveredApiEndpoint> RemovedEndpoints,
    DateTime GeneratedAtUtc
);
