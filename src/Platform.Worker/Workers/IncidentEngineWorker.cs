using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Operations;

namespace Platform.Worker.Workers;

public class IncidentEngineWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<IncidentEngineWorker> logger) : BackgroundService
{
    private readonly TimeSpan _cycleInterval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("IncidentEngineWorker background service started (interval: {Interval}s)", _cycleInterval.TotalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var incidentEngine = scope.ServiceProvider.GetRequiredService<IIncidentEngineService>();

                await incidentEngine.RunDetectionCycleAsync(stoppingToken);
            }
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error in IncidentEngineWorker cycle");
            }

            try
            {
                await Task.Delay(_cycleInterval, stoppingToken);
            }
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        logger.LogInformation("IncidentEngineWorker background service stopped.");
    }
}
