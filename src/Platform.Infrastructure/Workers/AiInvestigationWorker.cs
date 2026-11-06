using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Services;

namespace Platform.Infrastructure.Workers;

public class AiInvestigationWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;

    private readonly ILogger<AiInvestigationWorker> _logger;
    private readonly string _workerInstanceId = Guid.NewGuid().ToString("N")[..8];

    public AiInvestigationWorker(IServiceScopeFactory scopeFactory, ILogger<AiInvestigationWorker> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AiInvestigationWorker [{WorkerId}] started. Single worker concurrency = 1.", _workerInstanceId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<IPlatformDbContext>();
                var engine = scope.ServiceProvider.GetRequiredService<AiInvestigationEngine>();

                // Check Admin Global Pause
                var isGlobalEnabledSetting = await dbContext.SystemSettings
                    .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", stoppingToken);

                if (isGlobalEnabledSetting != null && string.Equals(isGlobalEnabledSetting.Value, "false", StringComparison.OrdinalIgnoreCase))
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    continue;
                }

                var jobToClaim = await ClaimNextJobAsync(dbContext, stoppingToken);

                if (jobToClaim != null)
                {
                    _logger.LogInformation("Worker [{WorkerId}] claimed investigation job '{JobId}' (LeaseToken='{Token}'). Executing engine...", _workerInstanceId, jobToClaim.Id, jobToClaim.ClaimToken);
                    await engine.ExecuteInvestigationAsync(jobToClaim.Id, jobToClaim.ClaimToken, stoppingToken);

                }
                else
                {
                    await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Worker [{WorkerId}] encountered error during job claiming loop.", _workerInstanceId);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        _logger.LogInformation("AiInvestigationWorker [{WorkerId}] stopped.", _workerInstanceId);
    }

    private async Task<AiInvestigationJob?> ClaimNextJobAsync(IPlatformDbContext dbContext, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        // Full-content AI stages can legitimately run for many minutes; only reclaim
        // jobs whose heartbeat has been silent for longer than any single stage should take.
        var staleHeartbeatCutoff = now.AddMinutes(-20);

        var candidateId = await dbContext.AiInvestigationJobs
            .Where(j => j.Status == JobStatus.Queued ||
                        (j.Status == JobStatus.Running &&
                         (j.LastHeartbeatAtUtc == null || j.LastHeartbeatAtUtc < staleHeartbeatCutoff)))
            .OrderBy(j => j.QueuedAtUtc)
            .Select(j => (Guid?)j.Id)
            .FirstOrDefaultAsync(ct);

        if (candidateId == null) return null;

        var claimToken = Guid.NewGuid();

        // Atomic compare-and-set: only the worker that observes the job in a claimable
        // state transitions it to Running. Concurrent workers receive 0 rows and retry.
        var updated = await dbContext.AiInvestigationJobs
            .Where(j => j.Id == candidateId &&
                        (j.Status == JobStatus.Queued ||
                         (j.Status == JobStatus.Running &&
                          (j.LastHeartbeatAtUtc == null || j.LastHeartbeatAtUtc < staleHeartbeatCutoff))))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(j => j.Status, JobStatus.Running)
                .SetProperty(j => j.WorkerId, _workerInstanceId)
                .SetProperty(j => j.ClaimToken, claimToken)
                .SetProperty(j => j.StartedAtUtc, j => j.StartedAtUtc ?? now)
                .SetProperty(j => j.LastHeartbeatAtUtc, now), ct);

        if (updated == 0) return null;

        return await dbContext.AiInvestigationJobs
            .AsNoTracking()
            .FirstOrDefaultAsync(j => j.ClaimToken == claimToken && j.WorkerId == _workerInstanceId, ct);
    }
}
