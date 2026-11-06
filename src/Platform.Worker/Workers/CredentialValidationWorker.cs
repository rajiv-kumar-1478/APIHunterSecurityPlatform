using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Platform.Application.Contracts;
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

        // 2. Parse job payload (candidate + optional AI validation plan)
        Guid candidateId = Guid.Empty;
        bool aiGenerated = false;
        bool approved = false;
        string? providerName = null;
        AiValidationPlan? validationPlan = null;

        try
        {
            using var doc = JsonDocument.Parse(job.PayloadJson ?? "{}");
            var payload = doc.RootElement;

            if (payload.TryGetProperty("candidateId", out var cProp) &&
                cProp.ValueKind == JsonValueKind.String)
            {
                candidateId = cProp.GetGuid();
            }

            aiGenerated = payload.TryGetProperty("aiGenerated", out var aiProp) &&
                          aiProp.ValueKind == JsonValueKind.True;

            approved = payload.TryGetProperty("approved", out var approvedProp) &&
                       approvedProp.ValueKind == JsonValueKind.True;

            if (payload.TryGetProperty("providerName", out var pProp) &&
                pProp.ValueKind == JsonValueKind.String)
            {
                providerName = pProp.GetString();
            }

            if (payload.TryGetProperty("validationPlan", out var planProp))
            {
                validationPlan = DeserializePlan(planProp);
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Validation job '{JobId}' has an unreadable payload.", job.Id);
        }

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

        // 3. Approval gate: no live credential is validated without an explicit
        // administrator approval, regardless of whether the plan was AI-generated.
        if (!approved)
        {
            job.Status = JobStatus.Paused;
            job.WorkerInstanceId = null;
            job.StartedAtUtc = null;
            job.LastHeartbeatAtUtc = null;
            await dbContext.SaveChangesAsync(ct);
            _logger.LogInformation(
                "Validation job '{JobId}' is awaiting administrator approval; returned to Paused.", job.Id);
            return true;
        }

        if (aiGenerated && validationPlan is null)
        {
            job.Status = JobStatus.Failed;
            job.ErrorMessage = "AI-generated validation job is missing a validation plan.";
            job.CompletedAtUtc = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(ct);
            return true;
        }

        // 4. Execute candidate validation
        try
        {
            var valResult = aiGenerated
                ? await validationService.ValidateWithAiPlanAsync(
                    candidateId, validationPlan!, providerName ?? "Unknown", job.Id, ct)
                : await validationService.ValidateCandidateAsync(candidateId, job.Id, ct);

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

    private static readonly JsonSerializerOptions PayloadJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static AiValidationPlan? DeserializePlan(JsonElement planElement)
    {
        if (planElement.ValueKind == JsonValueKind.String)
        {
            var raw = planElement.GetString();
            if (string.IsNullOrWhiteSpace(raw)) return null;

            try
            {
                using var nested = JsonDocument.Parse(raw);
                return DeserializePlan(nested.RootElement);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        if (planElement.ValueKind != JsonValueKind.Object) return null;

        try
        {
            return planElement.Deserialize<AiValidationPlan>(PayloadJsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
