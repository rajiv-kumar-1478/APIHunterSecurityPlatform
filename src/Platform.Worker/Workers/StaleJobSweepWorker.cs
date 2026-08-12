using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Services;

namespace Platform.Worker.Workers;

public class StaleJobSweepWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<StaleJobSweepWorker> logger) : BackgroundService
{
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
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error sweeping stale jobs in worker loop");
            }

            // Run sweep every 60 seconds
            await Task.Delay(60000, stoppingToken);
        }

        logger.LogInformation("StaleJobSweepWorker stopping.");
    }
}
