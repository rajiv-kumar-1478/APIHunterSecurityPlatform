using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Workers;

/// <summary>
/// Continuous Revalidation Worker (Phase 6 Step 6).
///
/// Responsibilities:
///   Loop A — Scheduling: determine which candidates are overdue, enqueue CredentialValidation jobs.
///   Loop B — Processing: call ValidationStateChangeProcessor to handle completed results.
///
/// This worker is a SCHEDULER/ORCHESTRATOR only.
/// It does NOT validate credentials directly.
/// It does NOT update findings, risk scores, or graph nodes directly.
/// All validation is performed by the existing CredentialValidationWorker (unchanged).
/// All consequence processing is performed by ValidationStateChangeProcessor.
/// </summary>
public class ContinuousRevalidationWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ContinuousRevalidationWorker> _logger;
    private readonly string _workerId = $"RevalidationWorker-{Guid.NewGuid():N}"[..24];

    public ContinuousRevalidationWorker(
        IServiceScopeFactory scopeFactory,
        ILogger<ContinuousRevalidationWorker> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ContinuousRevalidationWorker [{WorkerId}] started.", _workerId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var options = scope.ServiceProvider.GetRequiredService<IOptions<ContinuousRevalidationOptions>>().Value;

                if (!options.GlobalEnabled)
                {
                    _logger.LogDebug("ContinuousRevalidation is globally disabled via options. Sleeping.");
                    await Task.Delay(TimeSpan.FromSeconds(options.SchedulingIntervalSeconds), stoppingToken);
                    continue;
                }

                var dbContext = scope.ServiceProvider.GetRequiredService<IPlatformDbContext>();

                // Check system-settings kill switch (runtime admin override)
                var runtimeSwitch = await dbContext.SystemSettings
                    .FirstOrDefaultAsync(s => s.Key == "revalidation.global_enabled", stoppingToken);

                if (runtimeSwitch != null &&
                    string.Equals(runtimeSwitch.Value, "false", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogDebug("ContinuousRevalidation paused via SystemSettings. Sleeping.");
                    await Task.Delay(TimeSpan.FromSeconds(options.SchedulingIntervalSeconds), stoppingToken);
                    continue;
                }

                // ── Loop A: Schedule overdue candidates ────────────────────
                int scheduledCount = await ScheduleOverdueCandidatesAsync(scope, dbContext, options, stoppingToken);
                _logger.LogInformation("ContinuousRevalidationWorker [{WorkerId}] scheduled {Count} revalidation jobs.", _workerId, scheduledCount);

                // ── Loop B: Process completed results ──────────────────────
                var processor = scope.ServiceProvider.GetRequiredService<ValidationStateChangeProcessor>();
                var report = await processor.ProcessPendingResultsAsync(stoppingToken);
                _logger.LogInformation(
                    "ContinuousRevalidationWorker [{WorkerId}] processing pass: Processed={P}, Skipped={S}, Errors={E}.",
                    _workerId, report.ProcessedCount, report.SkippedCount, report.ErrorCount);

                await Task.Delay(TimeSpan.FromSeconds(options.SchedulingIntervalSeconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ContinuousRevalidationWorker [{WorkerId}] encountered an unexpected error. Retrying in 10 seconds.", _workerId);
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }

        _logger.LogInformation("ContinuousRevalidationWorker [{WorkerId}] stopped.", _workerId);
    }

    // ─── Loop A: Eligibility query + enqueue ─────────────────────────────────

    private async Task<int> ScheduleOverdueCandidatesAsync(
        IServiceScope scope,
        IPlatformDbContext dbContext,
        ContinuousRevalidationOptions options,
        CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var validationCutoff = now.AddHours(-options.MinRevalidationIntervalHours);

        // 1. Find candidate IDs that already have an in-flight validation job
        //    (Queued or Running) — duplicate-job prevention.
        var inFlightCandidateIds = await dbContext.AnalysisJobs
            .Where(j => j.JobType == JobType.CredentialValidation
                     && (j.Status == JobStatus.Queued || j.Status == JobStatus.Running))
            .Select(j => j.TargetEntityId)
            .Distinct()
            .ToListAsync(ct);

        // 2. Find the most recent *non-transient* (definitive) validation result per candidate.
        //    This is the LastCompletedValidation for the two-timeline model.
        //    Transient results (RateLimited, Unavailable, ValidationError, Unknown, Pending)
        //    are excluded from this query so they cannot suppress overdue scheduling.
        var transientStatuses = new[]
        {
            ValidationStatus.RateLimited, ValidationStatus.Unavailable,
            ValidationStatus.ValidationError, ValidationStatus.Unknown, ValidationStatus.Pending
        };

        var lastDefinitiveResultByCandidate = await dbContext.CredentialValidationResults
            .Where(r => !transientStatuses.Contains(r.Status))
            .GroupBy(r => r.CandidateId)
            .Select(g => new
            {
                CandidateId = g.Key,
                LastValidatedAtUtc = g.Max(r => r.ValidatedAtUtc),
                // RetryAfterUtc: if the most recent result (by ValidatedAtUtc) has a RetryAfterUtc, respect it.
                // We pick the max RetryAfterUtc from the group as a conservative bound.
                RetryAfterUtc = g.Max(r => r.RetryAfterUtc)
            })
            .ToListAsync(ct);

        var definitiveByCandidate = lastDefinitiveResultByCandidate
            .ToDictionary(x => x.CandidateId);

        // 3. Load all candidates
        var allCandidates = await dbContext.CredentialCandidates
            .Where(c => !inFlightCandidateIds.Contains(c.Id))
            .ToListAsync(ct);

        // 4. Filter to overdue candidates using two-timeline model
        var overdueCandidates = allCandidates
            .Where(c =>
            {
                if (definitiveByCandidate.TryGetValue(c.Id, out var last))
                {
                    // Respect provider RetryAfterUtc if set
                    if (last.RetryAfterUtc.HasValue && last.RetryAfterUtc.Value > now)
                        return false;

                    // Overdue if last definitive validation is older than the minimum interval
                    return last.LastValidatedAtUtc < validationCutoff;
                }
                // No definitive result ever — always overdue
                return true;
            })
            .OrderBy(c =>
            {
                if (definitiveByCandidate.TryGetValue(c.Id, out var last))
                    return last.LastValidatedAtUtc;
                return DateTime.MinValue; // Never validated → highest priority
            })
            .Take(options.MaxCandidatesPerPass)
            .ToList();

        if (!overdueCandidates.Any()) return 0;

        // 5. Enqueue via existing CredentialValidationService (unchanged)
        var validationService = scope.ServiceProvider.GetRequiredService<CredentialValidationService>();
        int scheduledCount = 0;

        foreach (var candidate in overdueCandidates)
        {
            try
            {
                await validationService.EnqueueValidationJobAsync(candidate.Id, ct);
                scheduledCount++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enqueue revalidation job for candidate '{CandidateId}'. Skipping.", candidate.Id);
            }
        }

        return scheduledCount;
    }
}
