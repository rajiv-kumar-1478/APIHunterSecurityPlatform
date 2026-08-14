using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Operational read service for scan campaign observability, health metrics,
/// execution history, and diagnostics.
///
/// STRICT READ-ONLY INVARIANT:
/// This service provides query access over persisted state in scan_campaigns,
/// campaign_execution_audit_logs, and security_scan_jobs. It contains zero dispatch,
/// claim, retry, or mutation logic.
/// </summary>
public interface ICampaignObservabilityService
{
    /// <summary>
    /// Evaluates tenant-scoped operational health for scan campaigns with strict precedence:
    /// FailClosed > Unavailable > Degraded > NotConfigured > Healthy.
    /// </summary>
    Task<CampaignOperationalHealthDto> GetTenantHealthAsync(Guid tenantId, CancellationToken ct = default);

    /// <summary>
    /// Returns paginated, correlated execution history combining audit logs with linked scan job outcomes.
    /// </summary>
    Task<IReadOnlyList<CampaignExecutionHistoryEntryDto>> GetCampaignExecutionHistoryAsync(
        Guid tenantId,
        Guid campaignId,
        int page = 1,
        int pageSize = 50,
        DateTime? sinceUtc = null,
        SchedulerDecision? decision = null,
        CancellationToken ct = default);

    /// <summary>
    /// Provides failure streak, auto-pause rationale, and recovery audit diagnostics for a specific campaign.
    /// </summary>
    Task<CampaignDiagnosticsDto?> GetCampaignDiagnosticsAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default);

    /// <summary>
    /// Calculates tenant-scoped aggregate window metrics over a specified lookback window.
    /// </summary>
    Task<CampaignWindowMetricsDto> GetTenantWindowMetricsAsync(
        Guid tenantId,
        TimeSpan window,
        CancellationToken ct = default);
}
