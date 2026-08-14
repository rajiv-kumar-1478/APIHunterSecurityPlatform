using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative campaign dispatch engine.
/// Responsibilities: due-campaign query, atomic claim/concurrency-safe dispatch,
/// idempotency guard, stuck-job recovery.
/// Does NOT contain scanner execution logic; that remains in Phase 8 GenericScanWorker.
/// </summary>
public interface ICampaignDispatchService
{
    /// <summary>
    /// Runs one complete scheduler polling tick:
    /// finds Active campaigns with NextRunUtc &lt;= now, atomically claims and dispatches each.
    /// Returns a summary of all outcomes for logging/alerting.
    /// </summary>
    Task<CampaignSchedulerTickResult> RunSchedulerTickAsync(CancellationToken ct = default);

    /// <summary>
    /// Identifies SecurityScanJobs in Running state whose LastHeartbeatUtc has exceeded
    /// the configured stuck threshold. Atomically claims each via JobVersion concurrency token:
    ///   - if the live worker heartbeated first, DbUpdateConcurrencyException aborts recovery
    ///   - if recovery wins: Status = TimedOut, reason = CAMPAIGN_JOB_STUCK
    /// Increments ConsecutiveFailuresCount and auto-pauses campaign at threshold.
    /// Returns the number of jobs successfully recovered.
    /// </summary>
    Task<int> RecoverStuckJobsAsync(CancellationToken ct = default);

    /// <summary>
    /// Called by ScanPostExecutionProcessor after a campaign scan job completes.
    /// On success: ConsecutiveFailuresCount = 0.
    /// On failure: ConsecutiveFailuresCount++, auto-pauses at threshold.
    /// No-op for jobs without a CampaignId.
    /// </summary>
    Task ProcessJobOutcomeAsync(Guid scanJobId, bool success, CancellationToken ct = default);
}
