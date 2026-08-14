using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Services;

namespace Platform.Infrastructure.Workers;

/// <summary>
/// Long-running background service that drives the continuous campaign scheduler.
///
/// Responsibilities:
///   1. Scheduler tick: every TickIntervalSeconds → ICampaignDispatchService.RunSchedulerTickAsync()
///      Finds Active campaigns with NextRunUtc &lt;= now and atomically dispatches SecurityScanJobs.
///
///   2. Recovery tick: every RecoveryIntervalSeconds → ICampaignDispatchService.RecoverStuckJobsAsync()
///      Finds Running jobs whose LastHeartbeatUtc exceeds the stuck threshold and atomically
///      transitions them to TimedOut (using JobVersion optimistic concurrency to avoid racing
///      with a live worker that is actively heartbeating).
///
/// HEARTBEAT NOTE:
///   This worker does NOT heartbeat jobs — that is the responsibility of GenericScanWorker,
///   which must call a periodic heartbeat update (bumping LastHeartbeatUtc + JobVersion)
///   at the rate defined by CampaignSchedulerOptions.HeartbeatIntervalSeconds.
///   The recovery loop uses the resulting staleness to detect genuinely stuck jobs.
///
/// SCOPED SERVICE PATTERN:
///   ICampaignDispatchService is scoped (it depends on IPlatformDbContext which is scoped).
///   This worker uses IServiceScopeFactory to create a fresh scope per tick, which is the
///   standard .NET pattern for consuming scoped services from a singleton BackgroundService.
/// </summary>
public sealed class CampaignSchedulerWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly CampaignSchedulerOptions _options;
    private readonly ILogger<CampaignSchedulerWorker> _logger;

    public CampaignSchedulerWorker(
        IServiceScopeFactory scopeFactory,
        IOptions<CampaignSchedulerOptions> options,
        ILogger<CampaignSchedulerWorker> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "CampaignSchedulerWorker starting. TickInterval={Tick}s RecoveryInterval={Recovery}s HeartbeatInterval={Heartbeat}s StuckThreshold={Stuck}min GlobalEnabled={Enabled}",
            _options.TickIntervalSeconds, _options.RecoveryIntervalSeconds,
            _options.HeartbeatIntervalSeconds, _options.StuckJobThresholdMinutes,
            _options.GlobalEnabled);

        // Run both loops concurrently within the same background service
        var schedulerLoop = RunSchedulerLoopAsync(stoppingToken);
        var recoveryLoop = RunRecoveryLoopAsync(stoppingToken);

        await Task.WhenAll(schedulerLoop, recoveryLoop);

        _logger.LogInformation("CampaignSchedulerWorker stopped.");
    }

    // =========================================================================
    // Scheduler loop
    // =========================================================================

    private async Task RunSchedulerLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var dispatcher = scope.ServiceProvider.GetRequiredService<ICampaignDispatchService>();
                var result = await dispatcher.RunSchedulerTickAsync(ct);

                _logger.LogDebug(
                    "SchedulerTick: Evaluated={E} Dispatched={D} Skipped={S} ClaimLost={CL} Errors={Err}",
                    result.CampaignsEvaluated, result.Dispatched, result.Skipped, result.ClaimLost, result.Errors);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CampaignSchedulerWorker: Unhandled error in scheduler loop.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_options.TickIntervalSeconds), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    // =========================================================================
    // Recovery loop
    // =========================================================================

    private async Task RunRecoveryLoopAsync(CancellationToken ct)
    {
        // Stagger initial recovery by half the interval to avoid race with the first scheduler tick
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(_options.RecoveryIntervalSeconds / 2.0), ct);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var dispatcher = scope.ServiceProvider.GetRequiredService<ICampaignDispatchService>();
                var recovered = await dispatcher.RecoverStuckJobsAsync(ct);

                if (recovered > 0)
                {
                    _logger.LogWarning("CampaignSchedulerWorker: Recovery loop recovered {Count} stuck job(s).", recovered);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CampaignSchedulerWorker: Unhandled error in recovery loop.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_options.RecoveryIntervalSeconds), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
