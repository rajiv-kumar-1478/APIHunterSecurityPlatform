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
    /// the configured stuck threshold. JobVersion fences timeout recovery against a live
    /// heartbeat. Recovery commits the TimedOut state and audit atomically, then routes
    /// campaign accounting through ProcessJobOutcomeAsync.
    /// Returns the number of jobs successfully recovered, independent of later accounting races.
    /// </summary>
    Task<int> RecoverStuckJobsAsync(CancellationToken ct = default);

    /// <summary>
    /// Applies the earliest pending terminal outcome for a campaign. Durable job status,
    /// not the compatibility success argument, determines success or failure. Campaign
    /// counters/status and the per-job processed marker commit atomically.
    /// No-op for jobs without a CampaignId and defers nonterminal or out-of-order jobs.
    /// </summary>
    Task ProcessJobOutcomeAsync(Guid scanJobId, bool success, CancellationToken ct = default);
}
