using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Orchestration.Contracts;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Orchestration;

/// <summary>
/// Continuous intelligence pipeline orchestrator coordinating the complete deployment scan lifecycle:
/// JS Discovery -> Baseline Diffing -> Targeted AST/Secrets -> Verification Planning -> BugHunter Execution -> Finding Ingestion.
/// </summary>
public interface IDeploymentScanOrchestrator
{
    /// <summary>
    /// Executes the full deployment scan workflow with durable concurrency control and audit tracking.
    /// </summary>
    Task<DeploymentScanRecord> ExecuteDeploymentScanAsync(
        Guid scanJobId,
        Guid tenantId,
        string applicationId,
        string deploymentId,
        string? commitSha,
        string environment,
        string targetUrl,
        ApplicationScanPolicy? policy = null,
        IReadOnlyList<JavaScriptAsset>? baselineAssets = null,
        JsAttackSurfaceGraph? baselineGraph = null,
        CancellationToken ct = default);
}
