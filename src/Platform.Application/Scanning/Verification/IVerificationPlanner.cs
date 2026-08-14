using System;
using System.Collections.Generic;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Verification;

/// <summary>
/// Authoritative planner generating prioritized BugHunter active verification plans
/// from the Attack Surface Graph and deployment diffs.
/// </summary>
public interface IVerificationPlanner
{
    /// <summary>
    /// Builds a prioritized BugHunterExecutionPlan from the discovered attack surface and incremental diff.
    /// </summary>
    BugHunterExecutionPlan GeneratePlan(
        Guid scanJobId,
        ScanTriggerSource triggerSource,
        JsAttackSurfaceGraph currentGraph,
        JsAttackSurfaceDiff? surfaceDiff = null,
        IReadOnlyList<string>? internalHosts = null);
}
