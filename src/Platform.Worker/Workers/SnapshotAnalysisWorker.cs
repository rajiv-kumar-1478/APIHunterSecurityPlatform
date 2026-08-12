using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Services;
using Platform.Domain.Enums;

namespace Platform.Worker.Workers;

public class SnapshotAnalysisWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<SnapshotAnalysisWorker> logger) : BackgroundService
{
    private readonly string _workerInstanceId = $"AnalysisWorker-{Environment.MachineName}-{Guid.NewGuid().ToString()[..8]}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("SnapshotAnalysisWorker starting (Instance: {InstanceId})", _workerInstanceId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var jobOrchestrator = scope.ServiceProvider.GetRequiredService<JobOrchestrationService>();
                var detectionService = scope.ServiceProvider.GetRequiredService<SecretDetectionService>();

                var job = await jobOrchestrator.ClaimNextJobAsync(_workerInstanceId, stoppingToken);

                if (job == null || job.JobType != JobType.SnapshotAnalysis)
                {
                    await Task.Delay(3000, stoppingToken);
                    continue;
                }

                logger.LogInformation("Processing SnapshotAnalysis job {JobId} for Snapshot {SnapshotId}...", job.Id, job.TargetEntityId);

                try
                {
                    var count = await detectionService.AnalyzeSnapshotAsync(
                        job.TargetEntityId,
                        onFileProcessed: fileId =>
                        {
                            // Update checkpointing & heartbeat asynchronously
                            _ = jobOrchestrator.UpdateCheckpointAsync(job.Id, fileId, stoppingToken);
                        },
                        ct: stoppingToken);

                    await jobOrchestrator.CompleteJobAsync(job.Id, System.Text.Json.JsonSerializer.Serialize(new { CandidatesFound = count }), stoppingToken);
                    logger.LogInformation("Successfully completed snapshot analysis job {JobId} (Found {Count} candidate occurrences)", job.Id, count);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error executing snapshot analysis job {JobId}", job.Id);
                    await jobOrchestrator.FailJobAsync(job.Id, ex.Message, stoppingToken);
                }
            }
            catch (TaskCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error in SnapshotAnalysisWorker loop");
                await Task.Delay(5000, stoppingToken);
            }
        }

        logger.LogInformation("SnapshotAnalysisWorker stopping.");
    }
}
