using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Maintains the execution lease for a claimed scan job. Every pulse is a single
/// database-side update that verifies worker ownership and increments JobVersion,
/// fencing the campaign recovery worker from timing out a live execution.
/// </summary>
public sealed class ScanJobHeartbeatService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ScanJobHeartbeatService> _logger;

    public ScanJobHeartbeatService(
        IServiceScopeFactory scopeFactory,
        ILogger<ScanJobHeartbeatService> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task RunAsync(
        Guid scanJobId,
        string workerInstanceId,
        TimeSpan interval,
        Action onLeaseLost,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workerInstanceId))
        {
            throw new ArgumentException("Worker instance ID is required for heartbeat ownership.", nameof(workerInstanceId));
        }

        ArgumentNullException.ThrowIfNull(onLeaseLost);

        var effectiveInterval = interval < TimeSpan.FromSeconds(1)
            ? TimeSpan.FromSeconds(1)
            : interval;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(effectiveInterval, cancellationToken);

                await using var scope = _scopeFactory.CreateAsyncScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
                var now = DateTime.UtcNow;

                var updated = await dbContext.SecurityScanJobs
                    .Where(job => job.Id == scanJobId
                               && job.Status == SecurityScanJobStatus.Running
                               && job.WorkerInstanceId == workerInstanceId)
                    .ExecuteUpdateAsync(updates => updates
                        .SetProperty(job => job.LastHeartbeatUtc, now)
                        .SetProperty(job => job.JobVersion, job => job.JobVersion + 1),
                        cancellationToken);

                if (updated == 0)
                {
                    _logger.LogWarning(
                        "Heartbeat lease lost for scan job '{ScanJobId}' by worker '{WorkerInstanceId}'.",
                        scanJobId,
                        workerInstanceId);
                    onLeaseLost();
                    return;
                }

                _logger.LogDebug(
                    "Heartbeat persisted for scan job '{ScanJobId}' by worker '{WorkerInstanceId}'.",
                    scanJobId,
                    workerInstanceId);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Heartbeat update failed for scan job '{ScanJobId}' owned by worker '{WorkerInstanceId}'. Retrying.",
                    scanJobId,
                    workerInstanceId);
            }
        }
    }
}
