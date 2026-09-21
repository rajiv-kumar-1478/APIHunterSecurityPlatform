using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
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

                var job = await jobOrchestrator.ClaimNextJobAsync(_workerInstanceId, JobType.SnapshotAnalysis, stoppingToken);

                if (job == null)
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

                    // Auto-chain Stage 3: AI Deep Investigation to uncover obfuscated, split, or missed credentials
                    try
                    {
                        var dbContext = scope.ServiceProvider.GetRequiredService<IPlatformDbContext>();
                        var snapshot = await dbContext.RepositorySnapshots
                            .AsNoTracking()
                            .FirstOrDefaultAsync(s => s.Id == job.TargetEntityId, stoppingToken);

                        if (snapshot != null)
                        {
                            var aiInvestigationService = scope.ServiceProvider.GetRequiredService<AiInvestigationService>();
                            await aiInvestigationService.TriggerInvestigationAsync(snapshot.RepositoryId, snapshot.Id, stoppingToken);
                            logger.LogInformation("Automatically dispatched AI Deep Investigation for Repository {RepoId}, Snapshot {SnapshotId}", snapshot.RepositoryId, snapshot.Id);
                        }
                    }
                    catch (Exception aiEx)
                    {
                        logger.LogWarning(aiEx, "Could not auto-dispatch AI Deep Investigation for Snapshot {SnapshotId}", job.TargetEntityId);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error executing snapshot analysis job {JobId}", job.Id);
                    await jobOrchestrator.FailJobAsync(job.Id, ex.Message, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error in SnapshotAnalysisWorker loop");
                try
                {
                    await Task.Delay(5000, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }

        logger.LogInformation("SnapshotAnalysisWorker stopping.");
    }
}
