using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Services;

namespace Platform.Worker.Workers;

public class RepositoryAcquisitionWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<RepositoryAcquisitionWorker> logger) : BackgroundService
{
    private readonly string _workerInstanceId = $"AcquisitionWorker-{Environment.MachineName}-{Guid.NewGuid().ToString()[..8]}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("RepositoryAcquisitionWorker starting (Instance: {InstanceId})", _workerInstanceId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var jobOrchestrator = scope.ServiceProvider.GetRequiredService<JobOrchestrationService>();
                var acquisitionService = scope.ServiceProvider.GetRequiredService<RepositoryAcquisitionService>();

                // Claim next RepositoryAcquisition job safely via FOR UPDATE SKIP LOCKED
                var job = await jobOrchestrator.ClaimNextJobAsync(_workerInstanceId, stoppingToken);

                if (job == null || job.JobType != Domain.Enums.JobType.RepositoryAcquisition)
                {
                    await Task.Delay(3000, stoppingToken);
                    continue;
                }

                logger.LogInformation("Processing RepositoryAcquisition job {JobId} for Repository {RepoId}...", job.Id, job.TargetEntityId);

                try
                {
                    await acquisitionService.AcquireSnapshotAsync(job.TargetEntityId, ct: stoppingToken);
                    await jobOrchestrator.CompleteJobAsync(job.Id, ct: stoppingToken);
                    logger.LogInformation("Successfully completed acquisition for job {JobId}", job.Id);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error processing acquisition job {JobId}", job.Id);
                    await jobOrchestrator.FailJobAsync(job.Id, ex.Message, stoppingToken);
                }
            }
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error in RepositoryAcquisitionWorker loop");
                await Task.Delay(5000, stoppingToken);
            }
        }

        logger.LogInformation("RepositoryAcquisitionWorker stopping.");
    }
}
