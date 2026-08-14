using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Orchestration.Contracts;

public enum DeploymentScanStage
{
    Queued = 1,
    ConcurrencyCheck = 2,
    PolicyEvaluation = 3,
    DiscoveringJs = 4,
    DiffingAssets = 5,
    AnalyzingAstAndSecrets = 6,
    PlanningVerification = 7,
    ExecutingBugHunter = 8,
    IngestingFindings = 9,
    Completed = 10,
    Failed = 11,
    SkippedByPolicy = 12
}

/// <summary>
/// Durable database-backed lease claim for application-level deployment concurrency control.
/// </summary>
public sealed record DeploymentScanLease(
    Guid LeaseId,
    Guid TenantId,
    string ApplicationId,
    Guid ScanJobId,
    DateTime AcquiredAtUtc,
    DateTime ExpiresAtUtc,
    DateTime LastHeartbeatAtUtc
);

/// <summary>
/// Configurable execution policy per application deployment.
/// </summary>
public sealed record ApplicationScanPolicy(
    string ApplicationId,
    int LeaseTimeoutMinutes = 15,
    int HeartbeatIntervalSeconds = 30,
    bool EnableActiveVerification = true,
    bool SkipIfJsUnchanged = false,
    IReadOnlySet<string>? AllowedEnvironments = null
);

/// <summary>
/// Authoritative record of an orchestrated deployment scan lifecycle.
/// </summary>
public sealed record DeploymentScanRecord(
    Guid ScanJobId,
    Guid TenantId,
    string ApplicationId,
    string DeploymentId,
    string? CommitSha,
    string Environment,
    string TargetUrl,
    DeploymentScanStage Stage,
    bool JsChanged,
    bool ApiSurfaceChanged,
    bool ActiveVerificationPerformed,
    int DiscoveredJsCount,
    int ChangedJsCount,
    int DiscoveredApisCount,
    int NewApisCount,
    int VerifiedFindingsCount,
    DateTime StartedAtUtc,
    DateTime? CompletedAtUtc = null,
    string? FailureReason = null
);
