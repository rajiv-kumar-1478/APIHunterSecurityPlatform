using System;
using Platform.Application.Scanning.Planning.Contracts;

namespace Platform.Application.Scanning.Planning;

/// <summary>
/// Authoritative capability-driven scan planning engine resolving dynamic tool sequences,
/// preference policies, prerequisite dependencies, and audit PlanHash.
/// </summary>
public interface IScanPlanningEngine
{
    /// <summary>
    /// Builds a deterministic, capability-resolved scan execution plan for an authorized target.
    /// </summary>
    ResolvedScanPlan PlanScan(ScanPlanningRequest request);
}
