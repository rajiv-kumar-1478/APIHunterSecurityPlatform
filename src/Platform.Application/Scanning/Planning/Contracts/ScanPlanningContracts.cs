using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Planning.Contracts;

public enum TargetAssetKind
{
    WebEndpoint = 1,
    Domain = 2,
    SourceRepository = 3,
    JavaScriptBundle = 4,
    ApiContract = 5
}

public enum ScannerExecutionPhase
{
    Discovery = 1,
    StaticAnalysis = 2,
    AttackSurfaceAnalysis = 3,
    ActiveVerification = 4,
    Ingestion = 5
}

/// <summary>
/// Policy governing tool selection preferences, concurrency, and multi-tool resolution for a given capability.
/// </summary>
public sealed record ScannerSelectionPolicy(
    string Capability,
    IReadOnlyList<string> PreferredToolKeys,
    bool AllowMultipleTools = false,
    int MaxTools = 1,
    bool RequireHealthyTool = true
);

/// <summary>
/// Authoritative diagnostic health report for a registered scanner tool adapter.
/// </summary>
public sealed record ToolDiagnosticReport(
    string ToolKey,
    string Version,
    ToolHealthStatus Status,
    bool IsContainerImageDigestValid,
    IReadOnlySet<string> DeclaredCapabilities,
    ScannerExecutionPhase ExecutionPhase,
    DateTime LastDiagnosticAtUtc,
    string? ErrorMessage = null
);

/// <summary>
/// Strongly-typed request to plan tool execution for an authorized target.
/// </summary>
public sealed record ScanPlanningRequest(
    Guid ScanJobId,
    Guid TenantId,
    string TargetUrl,
    TargetAssetKind TargetKind,
    SecurityScanProfileType Profile,
    IReadOnlySet<string>? RequiredCapabilities = null,
    IReadOnlySet<string>? DisabledToolKeys = null,
    IReadOnlyList<ScannerSelectionPolicy>? CustomSelectionPolicies = null
);

/// <summary>
/// A concrete planned tool adapter invocation in the execution sequence.
/// </summary>
public sealed record PlannedToolInvocation(
    string ToolKey,
    string Version,
    ScannerExecutionPhase Phase,
    IReadOnlyList<string> SatisfiedCapabilities,
    IReadOnlyList<string> RequiredPrerequisiteCapabilities,
    string SelectionReason
);

/// <summary>
/// Authoritative resolved scan plan with deterministic execution sequence, audit reasons, and PlanHash.
/// </summary>
public sealed record ResolvedScanPlan(
    Guid ScanJobId,
    Guid TenantId,
    TargetAssetKind TargetKind,
    SecurityScanProfileType Profile,
    IReadOnlyList<PlannedToolInvocation> PlannedInvocations,
    IReadOnlyList<string> ExecutionSequence,
    IReadOnlyDictionary<string, string> RuleSetVersions,
    IReadOnlyDictionary<string, string> SelectionReasons,
    string PlannerVersion,
    string PlanHash,
    DateTime PlannedAtUtc,
    string TargetUrl = ""
);
