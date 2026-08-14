using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript.Contracts;

public enum TaintSourceKind
{
    LocationHash,
    LocationSearch,
    LocationHref,
    DocumentReferrer,
    WindowName,
    PostMessageData,
    UrlSearchParams,
    Custom
}

public enum TaintSinkKind
{
    InnerHtml,
    OuterHtml,
    DocumentWrite,
    DocumentWriteln,
    Eval,
    TimerString,
    NavigationAssignment,
    Custom
}

public enum SanitizerKind
{
    None = 0,
    DomPurify = 1,
    EncodeUriComponent = 2,
    CustomOrUnverified = 3
}

/// <summary>
/// Structural taint propagation flow from an untrusted source to a dangerous DOM sink.
/// </summary>
public sealed record DataFlowTaintPath(
    Guid FlowId,
    string AssetUrl,
    TaintSourceKind SourceKind,
    string SourceExpression,
    int SourceLine,
    IReadOnlyList<string> TransformationHops,
    SanitizerKind DetectedSanitizer,
    bool IsSanitizerVerified,
    TaintSinkKind SinkKind,
    string SinkExpression,
    int SinkLine,
    string CodeSnippet,
    FindingConfidence Confidence,
    string FlowFingerprint
);

/// <summary>
/// Result of AST client-side data-flow and DOM-XSS intelligence analysis.
/// </summary>
public sealed record JsDataFlowAnalysisResult(
    Guid ScanJobId,
    IReadOnlyList<DataFlowTaintPath> DetectedFlows,
    int TotalSourcesIdentified,
    int TotalSinksIdentified,
    int BoundedAnalysisExhaustionCount,
    IReadOnlyList<FindingCandidate> FindingCandidates
);
