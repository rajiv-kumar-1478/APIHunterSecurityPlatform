using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Execution.Contracts;
using Platform.Application.Scanning.Planning.Contracts;

namespace Platform.Application.Scanning.Execution;

/// <summary>
/// Authoritative scanner execution engine managing sandbox execution, timeout guards,
/// resource isolation, per-tool invocation state, candidate ingestion, and execution read models.
/// </summary>
public interface IScanExecutionEngine
{
    /// <summary>
    /// Executes a resolved scan plan through platform-owned sandboxes and ingests findings.
    /// </summary>
    Task<PlanExecutionResult> ExecutePlanAsync(
        ResolvedScanPlan plan,
        CancellationToken ct = default);

    /// <summary>
    /// Retrieves the ordered tool execution summary and lifecycle timeline for a scan job.
    /// </summary>
    Task<ScanJobExecutionSummaryDto?> GetExecutionSummaryAsync(
        Guid scanJobId,
        Guid tenantId,
        CancellationToken ct = default);
}
