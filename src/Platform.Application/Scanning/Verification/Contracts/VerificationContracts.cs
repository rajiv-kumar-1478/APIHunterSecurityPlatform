using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.Verification.Contracts;

public enum ScanTriggerSource
{
    // External Triggers
    ScheduledCampaign = 1,
    DeploymentWebhook = 2,
    ManualOnDemand = 3,

    // Internal Derived Triggers
    IncrementalJsChange = 4,
    AssetChange = 5
}

public enum VerificationPriority
{
    Critical = 1,   // Newly introduced endpoint (highest priority for CI feedback)
    High = 2,       // Modified endpoint / sensitive parameters (id, role, auth)
    Medium = 3,     // Standard REST/GraphQL endpoints with query/body parameters
    Low = 4         // Static / unchanged baseline endpoints
}

/// <summary>
/// A concrete planned endpoint verification action assigned to BugHunter.
/// </summary>
public sealed record PlannedEndpointVerification(
    Guid PlanId,
    DiscoveredApiEndpoint Endpoint,
    VerificationPriority Priority,
    IReadOnlyList<string> RecommendedTestCategories,
    string Rationale
);

/// <summary>
/// Authoritative test plan generated from the Attack Surface Graph and deployment diff.
/// </summary>
public sealed record BugHunterExecutionPlan(
    Guid ScanJobId,
    ScanTriggerSource TriggerSource,
    IReadOnlyList<PlannedEndpointVerification> PrioritizedEndpoints,
    IReadOnlyList<string> DiscoveredInternalHosts,
    bool IsIncrementalOnly,
    int TotalEndpointsPlanned,
    DateTime PlannedAtUtc
);

/// <summary>
/// Strongly-typed payload submitted by CI/CD deployment integrations.
/// Note: Target URL is strictly resolved server-side from ApplicationId and is not supplied here.
/// </summary>
public sealed record DeploymentWebhookRequest(
    string ApplicationId,
    string DeploymentId,
    string? CommitSha = null,
    string? Environment = null,
    string? TriggeredBy = null,
    DateTime? DeployedAtUtc = null
);

/// <summary>
/// Server-side resolution result for an authorized deployment webhook.
/// </summary>
public sealed record DeploymentTargetResolution(
    Guid TenantId,
    string ApplicationId,
    string AuthorizedTargetUrl,
    string Environment,
    bool IsAuthorized
);
