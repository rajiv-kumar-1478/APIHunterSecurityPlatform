using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Application.Services;

public class AiInvestigationService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ICurrentUserContext _currentUser;

    public AiInvestigationService(IPlatformDbContext dbContext, ICurrentUserContext currentUser)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
    }

    public async Task<AiInvestigationJobDto> TriggerInvestigationAsync(Guid repositoryId, Guid snapshotId, CancellationToken ct = default)
    {
        var repoExists = await _dbContext.Repositories.AnyAsync(r => r.Id == repositoryId, ct);
        if (!repoExists) throw new KeyNotFoundException($"Repository with ID '{repositoryId}' was not found.");

        var snapshotExists = await _dbContext.RepositorySnapshots.AnyAsync(s => s.Id == snapshotId, ct);
        if (!snapshotExists) throw new KeyNotFoundException($"RepositorySnapshot with ID '{snapshotId}' was not found.");

        // Deduplication: Check if an active investigation job already exists for this (repository, snapshot)
        var activeJob = await _dbContext.AiInvestigationJobs
            .FirstOrDefaultAsync(j => j.RepositoryId == repositoryId && j.SnapshotId == snapshotId &&
                (j.Status == JobStatus.Queued || j.Status == JobStatus.Running || j.Status == JobStatus.Paused), ct);

        if (activeJob != null)
        {
            return ToDto(activeJob);
        }

        var job = new AiInvestigationJob
        {
            RepositoryId = repositoryId,
            SnapshotId = snapshotId,
            CurrentStage = AiInvestigationStageType.RepositoryMetadata,
            CompletedStagesCount = 0,
            Status = JobStatus.Queued,
            QueuedAtUtc = DateTime.UtcNow
        };

        _dbContext.AiInvestigationJobs.Add(job);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiInvestigationTriggered,
            UserId = _currentUser.UserId,
            ResourceType = "AiInvestigationJob",
            ResourceId = job.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { repositoryId, snapshotId }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
        return ToDto(job);
    }

    public async Task<List<AiInvestigationJobDto>> GetInvestigationsAsync(CancellationToken ct = default)
    {
        var jobs = await _dbContext.AiInvestigationJobs
            .Include(j => j.Repository)
            .OrderByDescending(j => j.QueuedAtUtc)
            .ToListAsync(ct);

        return jobs.Select(ToDto).ToList();
    }

    public async Task<AiInvestigationJobDetailsDto> GetInvestigationByIdAsync(Guid id, CancellationToken ct = default)
    {
        var job = await _dbContext.AiInvestigationJobs
            .Include(j => j.Repository)
            .Include(j => j.Snapshot)
            .Include(j => j.Checkpoints)
            .Include(j => j.Evidences)
            .FirstOrDefaultAsync(j => j.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI investigation job with ID '{id}' was not found.");

        return new AiInvestigationJobDetailsDto(
            ToDto(job),
            job.Checkpoints.Select(c => new AiCheckpointDto(c.Id, c.StageType.ToString(), c.CursorPosition, c.CompletedAtUtc)).ToList(),
            job.Evidences.Select(e => new AiEvidenceDto(e.Id, e.EvidenceType, e.FilePath, e.StartLine, e.EndLine, e.Confidence.ToString(), e.CreatedAtUtc)).ToList());
    }

    public async Task<AiInvestigationJobDto> PauseInvestigationAsync(Guid id, CancellationToken ct = default)
    {
        var job = await _dbContext.AiInvestigationJobs.FirstOrDefaultAsync(j => j.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI investigation job with ID '{id}' was not found.");

        job.Status = JobStatus.Paused;
        await _dbContext.SaveChangesAsync(ct);
        return ToDto(job);
    }

    public async Task<AiInvestigationJobDto> ResumeInvestigationAsync(Guid id, CancellationToken ct = default)
    {
        var job = await _dbContext.AiInvestigationJobs.FirstOrDefaultAsync(j => j.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI investigation job with ID '{id}' was not found.");

        job.Status = JobStatus.Queued;
        await _dbContext.SaveChangesAsync(ct);
        return ToDto(job);
    }

    public async Task<AiInvestigationJobDto> CancelInvestigationAsync(Guid id, CancellationToken ct = default)
    {
        var job = await _dbContext.AiInvestigationJobs.FirstOrDefaultAsync(j => j.Id == id, ct)
            ?? throw new KeyNotFoundException($"AI investigation job with ID '{id}' was not found.");

        job.Status = JobStatus.Cancelled;
        await _dbContext.SaveChangesAsync(ct);
        return ToDto(job);
    }

    private static AiInvestigationJobDto ToDto(AiInvestigationJob job)
    {
        return new AiInvestigationJobDto(
            job.Id,
            job.RepositoryId,
            job.Repository?.FullName ?? "Unknown",
            job.SnapshotId,
            job.CurrentStage.ToString(),
            job.CompletedStagesCount,
            job.ActiveProviderName,
            job.ActiveModelName,
            job.TotalPromptTokens,
            job.TotalCompletionTokens,
            job.Status.ToString(),
            job.ErrorMessage,
            job.QueuedAtUtc,
            job.StartedAtUtc,
            job.CompletedAtUtc);
    }
}

public record TriggerInvestigationRequest(Guid RepositoryId, Guid SnapshotId);

public record AiInvestigationJobDto(
    Guid Id,
    Guid RepositoryId,
    string RepositoryName,
    Guid SnapshotId,
    string CurrentStage,
    int CompletedStagesCount,
    string ActiveProviderName,
    string ActiveModelName,
    int TotalPromptTokens,
    int TotalCompletionTokens,
    string Status,
    string? ErrorMessage,
    DateTime QueuedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc);

public record AiCheckpointDto(
    Guid Id,
    string StageType,
    string CursorPosition,
    DateTime CompletedAtUtc);

public record AiEvidenceDto(
    Guid Id,
    string EvidenceType,
    string FilePath,
    int StartLine,
    int EndLine,
    string Confidence,
    DateTime CreatedAtUtc);

public record AiInvestigationJobDetailsDto(
    AiInvestigationJobDto Job,
    List<AiCheckpointDto> Checkpoints,
    List<AiEvidenceDto> Evidences);
