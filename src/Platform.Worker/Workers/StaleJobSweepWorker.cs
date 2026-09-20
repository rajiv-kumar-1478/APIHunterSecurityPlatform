using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Services;

namespace Platform.Worker.Workers;

public class StaleJobSweepWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<StaleJobSweepWorker> logger) : BackgroundService
{
    private readonly TimeSpan _sweepInterval = TimeSpan.FromSeconds(60);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("StaleJobSweepWorker starting...");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var jobOrchestrator = scope.ServiceProvider.GetRequiredService<JobOrchestrationService>();

                var sweptCount = await jobOrchestrator.SweepStaleJobsAsync(staleTimeoutMinutes: 5, ct: stoppingToken);
                if (sweptCount > 0)
                {
                    logger.LogWarning("Swept and re-queued {Count} stale jobs", sweptCount);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error sweeping stale jobs in worker loop");
            }

            try
            {
                await Task.Delay(_sweepInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        logger.LogInformation("StaleJobSweepWorker stopping.");
    }
}
