using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Worker.Workers;

public class CredentialValidationWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CredentialValidationWorker> _logger;
    private readonly string _workerId = $"ValidationWorker-{Environment.MachineName}-{Guid.NewGuid():N}[..8]";

    public CredentialValidationWorker(
        IServiceProvider serviceProvider,
        ILogger<CredentialValidationWorker> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CredentialValidationWorker '{WorkerId}' starting durable validation processing loop.", _workerId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                bool processed = await ProcessNextValidationJobAsync(stoppingToken);
                if (!processed)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error in CredentialValidationWorker loop.");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        _logger.LogInformation("CredentialValidationWorker '{WorkerId}' stopped.", _workerId);
    }

    public async Task<bool> ProcessNextValidationJobAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IPlatformDbContext>();
        var validationService = scope.ServiceProvider.GetRequiredService<CredentialValidationService>();

        // 1. Claim next pending CredentialValidation job atomically
        var job = await dbContext.AnalysisJobs
            .Where(j => j.JobType == JobType.CredentialValidation && j.Status == JobStatus.Queued)
            .OrderBy(j => j.QueuedAtUtc)
            .FirstOrDefaultAsync(ct);

        if (job == null) return false;

        job.Status = JobStatus.Running;
        job.WorkerInstanceId = _workerId;
        job.StartedAtUtc = DateTime.UtcNow;



        try
        {
            await dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            _logger.LogWarning("Validation job '{JobId}' was claimed by another worker concurrently.", job.Id);
            return true;
        }

        // 2. Parse candidate ID from payload
        Guid candidateId = Guid.Empty;
        try
        {
            using var doc = JsonDocument.Parse(job.PayloadJson ?? "{}");
            if (doc.RootElement.TryGetProperty("candidateId", out var cProp))
            {
                candidateId = cProp.GetGuid();
            }
        }
        catch { }

        if (candidateId == Guid.Empty && job.TargetEntityId != Guid.Empty)
        {
            candidateId = job.TargetEntityId;
        }

        if (candidateId == Guid.Empty)
        {
            job.Status = JobStatus.Failed;
            job.ErrorMessage = "Invalid job payload: missing candidateId";
            job.CompletedAtUtc = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(ct);
            return true;
        }

        // 3. Execute candidate validation
        try
        {
            var valResult = await validationService.ValidateCandidateAsync(candidateId, job.Id, ct);

            job.Status = JobStatus.Succeeded;
            job.CompletedAtUtc = DateTime.UtcNow;
            job.ResultJson = JsonSerializer.Serialize(new
            {
                validationResultId = valResult.Id,
                status = valResult.Status.ToString(),
                providerName = valResult.ProviderName
            });

            await dbContext.SaveChangesAsync(ct);
            return true;
        }

        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed executing validation job '{JobId}' for candidate '{CandidateId}'.", job.Id, candidateId);

            job.Status = JobStatus.Failed;
            job.ErrorMessage = ex.Message;
            job.CompletedAtUtc = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(ct);
            return true;
        }
    }
}
