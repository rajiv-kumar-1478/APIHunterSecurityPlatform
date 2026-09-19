using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Scanning;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;

namespace Platform.Infrastructure.Workers;

/// <summary>
/// Claims queued security scan jobs and executes them through the authoritative
/// IScanWorker pipeline. Claims use a conditional database-side update so multiple
/// worker processes can poll concurrently without executing the same job.
/// </summary>
public sealed class SecurityScanJobConsumerWorker : BackgroundService
{
    private const int PendingOutcomeBatchSize = 25;

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ScanJobConsumerOptions _options;
    private readonly ILogger<SecurityScanJobConsumerWorker> _logger;
    private readonly Guid _tenantId;
    private readonly string _workerInstanceId;

    public SecurityScanJobConsumerWorker(
        IServiceScopeFactory scopeFactory,
        IOptions<ScanJobConsumerOptions> options,
        ITenantContext tenantContext,
        ILogger<SecurityScanJobConsumerWorker> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _tenantId = tenantContext?.TenantId ?? throw new ArgumentNullException(nameof(tenantContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _workerInstanceId = $"{Environment.MachineName}-{Guid.NewGuid():N}";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogWarning("SecurityScanJobConsumerWorker is disabled by configuration.");
            return;
        }

        var pollInterval = TimeSpan.FromSeconds(Math.Max(1, _options.PollIntervalSeconds));
        _logger.LogInformation(
            "SecurityScanJobConsumerWorker '{WorkerInstanceId}' started with PollInterval={PollInterval}.",
            _workerInstanceId,
            pollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ReconcilePendingCampaignOutcomesAsync(stoppingToken);

                var scanJobId = await ClaimNextJobAsync(stoppingToken);
                if (scanJobId.HasValue)
                {
                    await ExecuteClaimedJobAsync(scanJobId.Value, stoppingToken);
                    continue;
                }

                await Task.Delay(pollInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "SecurityScanJobConsumerWorker '{WorkerInstanceId}' encountered an unhandled loop error.",
                    _workerInstanceId);

                try
                {
                    await Task.Delay(pollInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        _logger.LogInformation(
            "SecurityScanJobConsumerWorker '{WorkerInstanceId}' stopped.",
            _workerInstanceId);
    }

    private async Task<Guid?> ClaimNextJobAsync(CancellationToken cancellationToken)
    {
        var attempts = Math.Max(1, _options.ClaimContentionRetries);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var candidateId = await dbContext.SecurityScanJobs
                .AsNoTracking()
                .Where(job => job.TenantId == _tenantId
                           && job.Status == SecurityScanJobStatus.Queued
                           && (job.CampaignId == null
                               || !dbContext.SecurityScanJobs.Any(other =>
                                   other.Id != job.Id
                                   && other.CampaignId == job.CampaignId
                                   && other.Status != SecurityScanJobStatus.Queued
                                   && other.CampaignOutcomeProcessedAtUtc == null)))
                .OrderBy(job => job.CreatedAtUtc)
                .ThenBy(job => job.Id)
                .Select(job => (Guid?)job.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (!candidateId.HasValue)
            {
                return null;
            }

            var now = DateTime.UtcNow;
            var claimed = await dbContext.SecurityScanJobs
                .Where(job => job.Id == candidateId.Value
                           && job.Status == SecurityScanJobStatus.Queued
                           && (job.CampaignId == null
                               || !dbContext.SecurityScanJobs.Any(other =>
                                   other.Id != job.Id
                                   && other.CampaignId == job.CampaignId
                                   && other.Status != SecurityScanJobStatus.Queued
                                   && other.CampaignOutcomeProcessedAtUtc == null)))
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(job => job.Status, SecurityScanJobStatus.Running)
                    .SetProperty(job => job.WorkerInstanceId, _workerInstanceId)
                    .SetProperty(job => job.LastHeartbeatUtc, now)
                    .SetProperty(job => job.StartedAtUtc, now)
                    .SetProperty(job => job.CurrentPhase, "Claimed")
                    .SetProperty(job => job.JobVersion, job => job.JobVersion + 1),
                    cancellationToken);

            if (claimed == 1)
            {
                _logger.LogInformation(
                    "Worker '{WorkerInstanceId}' claimed security scan job '{ScanJobId}'.",
                    _workerInstanceId,
                    candidateId.Value);
                return candidateId.Value;
            }

            _logger.LogDebug(
                "Worker '{WorkerInstanceId}' lost claim race for scan job '{ScanJobId}' (attempt {Attempt}/{Attempts}).",
                _workerInstanceId,
                candidateId.Value,
                attempt + 1,
                attempts);
        }

        return null;
    }

    private async Task ExecuteClaimedJobAsync(Guid scanJobId, CancellationToken cancellationToken)
    {
        SecurityScanJobStatus finalStatus;

        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var claimedJob = await dbContext.SecurityScanJobs
                .AsNoTracking()
                .FirstOrDefaultAsync(job => job.Id == scanJobId
                    && job.TenantId == _tenantId
                    && job.Status == SecurityScanJobStatus.Running
                    && job.WorkerInstanceId == _workerInstanceId,
                    cancellationToken)
                ?? throw new InvalidOperationException(
                    $"Scan job '{scanJobId}' is no longer a Running claim owned by worker '{_workerInstanceId}'.");

            // Re-check current authorization immediately before any provider secrets or tools are used.
            // A target may have been disabled or its queued URL may no longer match its registered scope.
            var scanJobService = scope.ServiceProvider.GetRequiredService<ScanJobService>();
            await scanJobService.ValidateTargetScopeAsync(
                claimedJob.TargetId,
                claimedJob.TargetUrl,
                cancellationToken);

            var scanWorker = scope.ServiceProvider.GetRequiredService<IScanWorker>();
            var result = await scanWorker.ExecuteClaimedScanJobAsync(
                scanJobId,
                _workerInstanceId,
                claimedJob.JobVersion,
                cancellationToken);
            finalStatus = result.Status;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await FinalizeCancelledClaimAsync(scanJobId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Worker '{WorkerInstanceId}' failed while executing scan job '{ScanJobId}'.",
                _workerInstanceId,
                scanJobId);

            await MarkClaimedJobFailedAsync(scanJobId, CancellationToken.None);
            finalStatus = await GetJobStatusAsync(scanJobId, CancellationToken.None)
                ?? SecurityScanJobStatus.Failed;
        }

        _logger.LogInformation(
            "Worker '{WorkerInstanceId}' finished scan job '{ScanJobId}' with status '{Status}'.",
            _workerInstanceId,
            scanJobId,
            finalStatus);

        using var outcomeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await ProcessCampaignOutcomeAsync(scanJobId, finalStatus, outcomeCts.Token);
    }

    private async Task FinalizeCancelledClaimAsync(Guid scanJobId)
    {
        try
        {
            using var cleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await MarkClaimedJobCancelledAsync(scanJobId, cleanupCts.Token);
            var finalStatus = await GetJobStatusAsync(scanJobId, cleanupCts.Token)
                ?? SecurityScanJobStatus.Cancelled;
            await ProcessCampaignOutcomeAsync(scanJobId, finalStatus, cleanupCts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to terminalize cancelled scan job '{ScanJobId}' during worker shutdown. Recovery will reconcile it.",
                scanJobId);
        }
    }

    private async Task MarkClaimedJobFailedAsync(Guid scanJobId, CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var now = DateTime.UtcNow;

        await dbContext.SecurityScanJobs
            .Where(job => job.Id == scanJobId
                       && job.Status == SecurityScanJobStatus.Running
                       && job.WorkerInstanceId == _workerInstanceId)
            .ExecuteUpdateAsync(updates => updates
                .SetProperty(job => job.Status, SecurityScanJobStatus.Failed)
                .SetProperty(job => job.FailureReason, "WORKER_EXECUTION_EXCEPTION")
                .SetProperty(job => job.CurrentPhase, "Failed")
                .SetProperty(job => job.CompletedAtUtc, now)
                .SetProperty(job => job.LastHeartbeatUtc, now)
                .SetProperty(job => job.JobVersion, job => job.JobVersion + 1),
                cancellationToken);
    }

    private async Task MarkClaimedJobCancelledAsync(Guid scanJobId, CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var now = DateTime.UtcNow;

        await dbContext.SecurityScanJobs
            .Where(job => job.Id == scanJobId
                       && job.Status == SecurityScanJobStatus.Running
                       && job.WorkerInstanceId == _workerInstanceId)
            .ExecuteUpdateAsync(updates => updates
                .SetProperty(job => job.Status, SecurityScanJobStatus.Cancelled)
                .SetProperty(job => job.FailureReason, "SCAN_JOB_CANCELLED")
                .SetProperty(job => job.CurrentPhase, "Cancelled")
                .SetProperty(job => job.CancelledAtUtc, now)
                .SetProperty(job => job.CompletedAtUtc, now)
                .SetProperty(job => job.LastHeartbeatUtc, now)
                .SetProperty(job => job.JobVersion, job => job.JobVersion + 1),
                cancellationToken);
    }

    private async Task<SecurityScanJobStatus?> GetJobStatusAsync(
        Guid scanJobId,
        CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        return await dbContext.SecurityScanJobs
            .AsNoTracking()
            .Where(job => job.Id == scanJobId)
            .Select(job => (SecurityScanJobStatus?)job.Status)
            .FirstOrDefaultAsync(cancellationToken);
    }

    private async Task ReconcilePendingCampaignOutcomesAsync(CancellationToken cancellationToken)
    {
        List<(Guid JobId, SecurityScanJobStatus Status)> pending;

        await using (var scope = _scopeFactory.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            pending = await dbContext.SecurityScanJobs
                .AsNoTracking()
                .Where(job => job.TenantId == _tenantId
                           && job.CampaignId != null
                           && job.CampaignOutcomeProcessedAtUtc == null
                           && (job.Status == SecurityScanJobStatus.Completed
                               || job.Status == SecurityScanJobStatus.CompletedWithWarnings
                               || job.Status == SecurityScanJobStatus.Partial
                               || job.Status == SecurityScanJobStatus.Failed
                               || job.Status == SecurityScanJobStatus.Cancelled
                               || job.Status == SecurityScanJobStatus.TimedOut
                               || job.Status == SecurityScanJobStatus.Blocked))
                .OrderBy(job => job.CompletedAtUtc ?? job.CreatedAtUtc)
                .ThenBy(job => job.CreatedAtUtc)
                .ThenBy(job => job.Id)
                .Take(PendingOutcomeBatchSize)
                .Select(job => new ValueTuple<Guid, SecurityScanJobStatus>(job.Id, job.Status))
                .ToListAsync(cancellationToken);
        }

        foreach (var (jobId, status) in pending)
        {
            await ProcessCampaignOutcomeAsync(jobId, status, cancellationToken);
        }
    }

    private async Task ProcessCampaignOutcomeAsync(
        Guid scanJobId,
        SecurityScanJobStatus finalStatus,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var dispatcher = scope.ServiceProvider.GetRequiredService<ICampaignDispatchService>();
            var succeeded = finalStatus is SecurityScanJobStatus.Completed
                or SecurityScanJobStatus.CompletedWithWarnings;

            await dispatcher.ProcessJobOutcomeAsync(scanJobId, succeeded, cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            _logger.LogDebug(
                "Campaign outcome for scan job '{ScanJobId}' was deferred by a concurrent update and remains eligible for reconciliation.",
                scanJobId);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to process campaign outcome for scan job '{ScanJobId}'. It remains eligible for reconciliation.",
                scanJobId);
        }
    }
}
