using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class JobOrchestrationService(
    IPlatformDbContext dbContext,
    IAuditService auditService,
    ILogger<JobOrchestrationService> logger)
{
    public async Task<AnalysisJob> CreateJobAsync(
        JobType jobType,
        string targetEntityType,
        Guid targetEntityId,
        int priority = 0,
        string? payloadJson = null,
        Guid? queuedByUserId = null,
        string? correlationId = null,
        CancellationToken ct = default)
    {
        var job = new AnalysisJob
        {
            JobType = jobType,
            TargetEntityType = targetEntityType,
            TargetEntityId = targetEntityId,
            Priority = priority,
            PayloadJson = payloadJson,
            QueuedByUserId = queuedByUserId,
            CorrelationId = correlationId ?? Guid.NewGuid().ToString(),
            Status = JobStatus.Queued,
            QueuedAtUtc = DateTime.UtcNow
        };

        dbContext.AnalysisJobs.Add(job);
        await dbContext.SaveChangesAsync(ct);

        await auditService.RecordAsync(
            AuditEventCode.JobCreated,
            queuedByUserId,
            null,
            "system",
            new { JobId = job.Id, JobType = jobType.ToString(), TargetEntityType = targetEntityType, TargetEntityId = targetEntityId },
            ct);

        return job;
    }

    public async Task<AnalysisJob?> ClaimNextJobAsync(string workerInstanceId, CancellationToken ct = default)
    {
        // Safe PostgreSQL row claiming with FOR UPDATE SKIP LOCKED
        // For testing/InMemory provider, fallback to LINQ optimistic lock
        var db = (DbContext)dbContext;
        if (!db.Database.IsRelational())
        {
            return await ClaimNextJobInMemoryAsync(workerInstanceId, ct);
        }

        var now = DateTime.UtcNow;

        // PostgreSQL-safe claim using Raw SQL inside transaction
        var sql = """
            WITH claimed AS (
                SELECT id 
                FROM analysis_jobs
                WHERE status = 'Queued' 
                   OR (status = 'Retrying' AND next_retry_at_utc <= {0})
                ORDER BY priority DESC, queued_at_utc ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE analysis_jobs
            SET status = 'Running',
                worker_instance_id = {1},
                started_at_utc = {0},
                last_heartbeat_at_utc = {0}
            FROM claimed
            WHERE analysis_jobs.id = claimed.id
            RETURNING analysis_jobs.*;
            """;

        var claimedJobs = await dbContext.AnalysisJobs
            .FromSqlRaw(sql, now, workerInstanceId)
            .ToListAsync(ct);

        return claimedJobs.FirstOrDefault();
    }

    private async Task<AnalysisJob?> ClaimNextJobInMemoryAsync(string workerInstanceId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var eligibleJob = await dbContext.AnalysisJobs
            .Where(j => j.Status == JobStatus.Queued || (j.Status == JobStatus.Retrying && j.NextRetryAtUtc <= now))
            .OrderByDescending(j => j.Priority)
            .ThenBy(j => j.QueuedAtUtc)
            .FirstOrDefaultAsync(ct);

        if (eligibleJob == null) return null;

        eligibleJob.Status = JobStatus.Running;
        eligibleJob.WorkerInstanceId = workerInstanceId;
        eligibleJob.StartedAtUtc = now;
        eligibleJob.LastHeartbeatAtUtc = now;

        await dbContext.SaveChangesAsync(ct);
        return eligibleJob;
    }

    public async Task UpdateHeartbeatAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job != null && job.Status == JobStatus.Running)
        {
            job.LastHeartbeatAtUtc = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(ct);
        }
    }

    public async Task UpdateCheckpointAsync(Guid jobId, Guid snapshotFileId, CancellationToken ct = default)
    {
        var job = await dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job != null)
        {
            job.CheckpointFileId = snapshotFileId;
            job.LastHeartbeatAtUtc = DateTime.UtcNow;
            await dbContext.SaveChangesAsync(ct);
        }
    }

    public async Task CompleteJobAsync(Guid jobId, string? resultJson = null, CancellationToken ct = default)
    {
        var job = await dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
            ?? throw new KeyNotFoundException($"Job {jobId} not found.");

        job.Status = JobStatus.Succeeded;
        job.CompletedAtUtc = DateTime.UtcNow;
        job.ResultJson = resultJson;

        await dbContext.SaveChangesAsync(ct);

        await auditService.RecordAsync(
            AuditEventCode.JobSucceeded,
            job.QueuedByUserId,
            null,
            "system",
            new { JobId = job.Id, JobType = job.JobType.ToString() },
            ct);
    }

    public async Task FailJobAsync(Guid jobId, string errorMessage, CancellationToken ct = default)
    {
        var job = await dbContext.AnalysisJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
            ?? throw new KeyNotFoundException($"Job {jobId} not found.");

        job.ErrorMessage = errorMessage;
        job.RetryCount++;

        if (job.RetryCount < job.MaxRetries)
        {
            job.Status = JobStatus.Retrying;
            // Exponential backoff: min(30s * 2^(retry-1), 10 minutes)
            var delaySeconds = Math.Min(30 * (int)Math.Pow(2, job.RetryCount - 1), 600);
            job.NextRetryAtUtc = DateTime.UtcNow.AddSeconds(delaySeconds);

            logger.LogWarning("Job {JobId} failed (attempt {Retry}/{Max}). Retrying at {NextRetry}",
                jobId, job.RetryCount, job.MaxRetries, job.NextRetryAtUtc);
        }
        else
        {
            job.Status = JobStatus.Failed;
            job.CompletedAtUtc = DateTime.UtcNow;

            logger.LogError("Job {JobId} failed permanently after {Max} retries: {Error}", jobId, job.MaxRetries, errorMessage);

            await auditService.RecordAsync(
                AuditEventCode.JobFailed,
                job.QueuedByUserId,
                null,
                "system",
                new { JobId = job.Id, JobType = job.JobType.ToString(), Error = errorMessage },
                ct);
        }

        await dbContext.SaveChangesAsync(ct);
    }

    public async Task<int> SweepStaleJobsAsync(int staleTimeoutMinutes = 5, CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-staleTimeoutMinutes);
        var staleJobs = await dbContext.AnalysisJobs
            .Where(j => j.Status == JobStatus.Running && (j.LastHeartbeatAtUtc == null || j.LastHeartbeatAtUtc < cutoff))
            .ToListAsync(ct);

        foreach (var job in staleJobs)
        {
            logger.LogWarning("Stale job detected: {JobId} (Last heartbeat: {Heartbeat}). Re-queuing.", job.Id, job.LastHeartbeatAtUtc);
            await FailJobAsync(job.Id, $"Stale worker heartbeat timeout (> {staleTimeoutMinutes} mins).", ct);
        }

        return staleJobs.Count;
    }
}

