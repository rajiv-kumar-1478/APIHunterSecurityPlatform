using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Common;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Orchestration;
using Platform.Application.Scanning.Orchestration.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class GenericScanWorker : IScanWorker
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IScanProviderSecretStore _secretStore;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly IEgressPolicyEngine _egressPolicyEngine;
    private readonly IScannerRuntimeSandbox? _runtimeSandbox;
    private readonly ScanExecutionOrchestrator _orchestrator;
    private readonly ScanPostExecutionProcessor? _postProcessor;
    private readonly ScannerRuntimeOptions _options;
    private readonly ScanJobHeartbeatService? _heartbeatService;
    private readonly TimeSpan _heartbeatInterval;
    private readonly IDeploymentScanOrchestrator? _deploymentOrchestrator;
    private readonly ILogger<GenericScanWorker> _logger;

    public GenericScanWorker(
        IPlatformDbContext dbContext,
        IScanProviderSecretStore secretStore,
        ScanToolRegistryService toolRegistryService,
        IEgressPolicyEngine egressPolicyEngine,
        IScannerRuntimeSandbox? runtimeSandbox,
        ILogger<GenericScanWorker> logger,
        ScanExecutionOrchestrator? orchestrator = null,
        ScanPostExecutionProcessor? postProcessor = null,
        ScannerRuntimeOptions? options = null,
        ScanJobHeartbeatService? heartbeatService = null,
        IOptions<CampaignSchedulerOptions>? campaignSchedulerOptions = null,
        IDeploymentScanOrchestrator? deploymentOrchestrator = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _toolRegistryService = toolRegistryService ?? throw new ArgumentNullException(nameof(toolRegistryService));
        _egressPolicyEngine = egressPolicyEngine ?? throw new ArgumentNullException(nameof(egressPolicyEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _runtimeSandbox = runtimeSandbox;
        _postProcessor = postProcessor;
        _deploymentOrchestrator = deploymentOrchestrator;
        _options = options ?? new ScannerRuntimeOptions();
        _heartbeatService = heartbeatService;
        _heartbeatInterval = TimeSpan.FromSeconds(
            campaignSchedulerOptions?.Value.HeartbeatIntervalSeconds ?? 120);

        _orchestrator = orchestrator ?? new ScanExecutionOrchestrator(
            _toolRegistryService,
            new ToolOutputParserProvider(),
            new ScanFindingIngestionEngine(_dbContext, Microsoft.Extensions.Logging.Abstractions.NullLogger<ScanFindingIngestionEngine>.Instance),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ScanExecutionOrchestrator>.Instance
        );
    }

    public async Task<ScanExecutionResult> ExecuteScanJobAsync(Guid scanJobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.FindAsync(new object[] { scanJobId }, ct);
        if (job == null)
        {
            throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");
        }

        return await ExecuteLoadedScanJobAsync(job, job.WorkerInstanceId, claimedExecution: false, ct);
    }

    public async Task<ScanExecutionResult> ExecuteClaimedScanJobAsync(
        Guid scanJobId,
        string expectedWorkerInstanceId,
        int expectedJobVersion,
        CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs
            .FirstOrDefaultAsync(candidate => candidate.Id == scanJobId
                && candidate.Status == SecurityScanJobStatus.Running
                && candidate.WorkerInstanceId == expectedWorkerInstanceId
                && candidate.JobVersion == expectedJobVersion,
                ct);

        if (job == null)
        {
            return await BuildCurrentLeaseLostResultAsync(scanJobId, ct);
        }

        return await ExecuteLoadedScanJobAsync(job, expectedWorkerInstanceId, claimedExecution: true, ct);
    }

    private async Task<ScanExecutionResult> ExecuteLoadedScanJobAsync(
        SecurityScanJob job,
        string? expectedWorkerInstanceId,
        bool claimedExecution,
        CancellationToken ct)
    {
        CancellationTokenSource? heartbeatCts = null;
        CancellationTokenSource? executionCts = null;
        Task heartbeatTask = Task.CompletedTask;
        string? scratchDirectory = null;
        var leaseLost = 0;

        void StartHeartbeat()
        {
            if (_heartbeatService == null || string.IsNullOrWhiteSpace(expectedWorkerInstanceId))
            {
                return;
            }

            var activeHeartbeatCts = new CancellationTokenSource();
            var activeExecutionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            heartbeatCts = activeHeartbeatCts;
            executionCts = activeExecutionCts;
            heartbeatTask = _heartbeatService.RunAsync(
                job.Id,
                expectedWorkerInstanceId,
                _heartbeatInterval,
                () =>
                {
                    if (Interlocked.Exchange(ref leaseLost, 1) == 0)
                    {
                        activeExecutionCts.Cancel();
                    }
                },
                activeHeartbeatCts.Token);
        }

        try
        {
            if (claimedExecution)
            {
                job.StartedAtUtc ??= DateTime.UtcNow;
                job.CurrentPhase = "Running";
                job.LastHeartbeatUtc = DateTime.UtcNow;
                job.JobVersion++;

                try
                {
                    await _dbContext.SaveChangesAsync(ct);
                }
                catch (DbUpdateConcurrencyException)
                {
                    _logger.LogWarning(
                        "Claimed scan job '{ScanJobId}' lost its execution lease before preflight initialization.",
                        job.Id);
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                // Claimed executions heartbeat before egress, secret access, scratch allocation,
                // or any other potentially long-running preflight work.
                StartHeartbeat();
            }

            var preflightToken = executionCts?.Token ?? ct;

            // 1. Mandatory Fail-Closed Egress Policy Evaluation
            EgressTarget egressTarget;
            try
            {
                egressTarget = await _egressPolicyEngine.EvaluateAndBuildTargetAsync(
                    job.TargetUrl,
                    TimeSpan.FromMinutes(10),
                    preflightToken);
                _logger.LogInformation(
                    "Worker validated target '{TargetUrl}' to canonical host '{CanonicalHost}' with {Count} approved IP(s).",
                    job.TargetUrl,
                    egressTarget.CanonicalHost,
                    egressTarget.ApprovedIpAddresses.Count);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Fail-closed egress policy evaluation failed for target '{TargetUrl}' (Job: {ScanJobId}).",
                    job.TargetUrl,
                    job.Id);

                if (!await StopHeartbeatAndRefreshJobAsync(
                        job,
                        expectedWorkerInstanceId,
                        heartbeatCts,
                        heartbeatTask,
                        claimedExecution))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                job.Status = SecurityScanJobStatus.Failed;
                job.FailureReason = $"EGRESS_POLICY_UNAVAILABLE: {ex.Message}";
                job.CurrentPhase = "Failed";
                job.CompletedAtUtc = DateTime.UtcNow;
                job.LastHeartbeatUtc = DateTime.UtcNow;
                job.JobVersion++;

                if (!await TrySaveTerminalChangesAsync(job, claimedExecution, ct))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
            }

            // 2. Strict Invariant: Active IScannerRuntimeSandbox is required (Fail Closed)
            if (_runtimeSandbox == null)
            {
                _logger.LogError(
                    "GenericScanWorker rejected job '{ScanJobId}': Active IScannerRuntimeSandbox is required.",
                    job.Id);

                if (!await StopHeartbeatAndRefreshJobAsync(
                        job,
                        expectedWorkerInstanceId,
                        heartbeatCts,
                        heartbeatTask,
                        claimedExecution))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                job.Status = SecurityScanJobStatus.Failed;
                job.FailureReason = "SECURITY_SANDBOX_REQUIRED: Active IScannerRuntimeSandbox is required.";
                job.CurrentPhase = "Failed";
                job.CompletedAtUtc = DateTime.UtcNow;
                job.LastHeartbeatUtc = DateTime.UtcNow;
                job.JobVersion++;

                if (!await TrySaveTerminalChangesAsync(job, claimedExecution, ct))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
            }

            var scratchRoot = _options.PlatformScratchRoot;
            scratchDirectory = Path.Combine(scratchRoot, job.Id.ToString("N"));

            GenericCliToolAdapter.ValidateScratchDirectoryPath(scratchDirectory, scratchRoot);
            Directory.CreateDirectory(scratchDirectory);
            GenericCliToolAdapter.VerifyNoReparsePointOrSymlink(scratchDirectory);

            _logger.LogInformation(
                "Worker allocated scratch directory '{ScratchDirectory}' for job '{ScanJobId}'.",
                scratchDirectory,
                job.Id);

            using ProviderSecretLease secretLease = await _secretStore.AcquireLeaseAsync(job.ProviderKey, preflightToken);

            if (!claimedExecution)
            {
                job.Status = SecurityScanJobStatus.Running;
                job.StartedAtUtc ??= DateTime.UtcNow;
                job.CurrentPhase = "Running";
                job.JobVersion++;
                await _dbContext.SaveChangesAsync(ct);
                StartHeartbeat();
            }

            // The orchestrator receives an untracked execution snapshot. Its progress
            // mutations must never enlist the heartbeat-owned tracked job in finding saves.
            var executionSnapshot = new SecurityScanJob
            {
                Id = job.Id,
                TenantId = job.TenantId,
                RepositoryId = job.RepositoryId,
                TargetId = job.TargetId,
                TargetUrl = job.TargetUrl,
                ScanProfile = job.ScanProfile
            };

            // 3. Phased Multi-Tool Pipeline Orchestration (or Deployment Scan Orchestration for CI/CD Webhooks)
            var executionToken = executionCts?.Token ?? ct;

            if (string.Equals(job.TriggeredBy, "CiCdWebhook", StringComparison.OrdinalIgnoreCase)
                && _deploymentOrchestrator != null)
            {
                var deploymentRecord = await _deploymentOrchestrator.ExecuteDeploymentScanAsync(
                    job.Id,
                    job.TenantId,
                    job.TargetUrl,
                    job.CorrelationId,
                    null,
                    "Production",
                    job.TargetUrl,
                    ct: executionToken);

                if (!await StopHeartbeatAndRefreshJobAsync(
                        job,
                        expectedWorkerInstanceId,
                        heartbeatCts,
                        heartbeatTask,
                        claimedExecution))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                job.Status = deploymentRecord.Stage == DeploymentScanStage.Completed
                    || deploymentRecord.Stage == DeploymentScanStage.SkippedByPolicy
                    ? SecurityScanJobStatus.Completed
                    : SecurityScanJobStatus.Failed;
                job.FailureReason = deploymentRecord.FailureReason;
                job.ExecutionReceiptJson = JsonSerializer.Serialize(deploymentRecord);
                job.TotalFindingsCount = deploymentRecord.VerifiedFindingsCount;
                job.ProgressPercentage = 100;
                job.CurrentPhase = "Completed";
                job.CompletedAtUtc = DateTime.UtcNow;
                job.LastHeartbeatUtc = DateTime.UtcNow;
                job.JobVersion++;

                if (!await TrySaveTerminalChangesAsync(job, claimedExecution, ct))
                {
                    return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
                }

                if (_postProcessor != null)
                {
                    try
                    {
                        await _postProcessor.ProcessPostScanLifecycleAsync(job.Id, ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Post-scan lifecycle processing failed for deployment job '{ScanJobId}'.", job.Id);
                    }
                }

                _logger.LogInformation(
                    "GenericScanWorker completed deployment scan job '{ScanJobId}' with status '{Status}'.",
                    job.Id,
                    job.Status);

                return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
            }

            var receipt = await _orchestrator.ExecutePipelineAsync(
                executionSnapshot,
                egressTarget,
                secretLease,
                scratchDirectory,
                _runtimeSandbox,
                null,
                executionToken);

            if (!await StopHeartbeatAndRefreshJobAsync(
                    job,
                    expectedWorkerInstanceId,
                    heartbeatCts,
                    heartbeatTask,
                    claimedExecution))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            job.Status = receipt.FinalJobStatus;
            job.FailureReason = receipt.FinalJobStatus == SecurityScanJobStatus.Failed ? receipt.Summary : null;
            job.ExecutionReceiptJson = JsonSerializer.Serialize(receipt);
            job.TotalFindingsCount = receipt.TotalFindingsCreated + receipt.TotalFindingsUpdated;
            job.ProgressPercentage = 100;
            job.CurrentPhase = "Completed";
            job.CompletedAtUtc = DateTime.UtcNow;
            job.LastHeartbeatUtc = DateTime.UtcNow;
            job.JobVersion++;

            if (!await TrySaveTerminalChangesAsync(job, claimedExecution, ct))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            if (_postProcessor != null)
            {
                try
                {
                    await _postProcessor.ProcessPostScanLifecycleAsync(job.Id, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Post-scan lifecycle processing failed for job '{ScanJobId}'.", job.Id);
                }
            }

            _logger.LogInformation(
                "GenericScanWorker completed job '{ScanJobId}' with status '{Status}'. Summary: {Summary}",
                job.Id,
                job.Status,
                receipt.Summary);
            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        catch (OperationCanceledException) when (Volatile.Read(ref leaseLost) == 1)
        {
            _logger.LogWarning(
                "Worker execution lease was lost for scan job '{ScanJobId}'. Cancelling active scan pipeline.",
                job.Id);

            await StopHeartbeatAndRefreshJobAsync(
                job,
                expectedWorkerInstanceId,
                heartbeatCts,
                heartbeatTask,
                claimedExecution);
            return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Worker execution cancelled for scan job '{ScanJobId}'.", job.Id);

            if (!await StopHeartbeatAndRefreshJobAsync(
                    job,
                    expectedWorkerInstanceId,
                    heartbeatCts,
                    heartbeatTask,
                    claimedExecution))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            job.Status = SecurityScanJobStatus.Cancelled;
            job.FailureReason = "SCAN_JOB_CANCELLED";
            job.CancelledAtUtc = DateTime.UtcNow;
            job.CompletedAtUtc = DateTime.UtcNow;
            job.CurrentPhase = "Cancelled";
            job.LastHeartbeatUtc = DateTime.UtcNow;
            job.JobVersion++;

            if (!await TrySaveTerminalChangesAsync(job, claimedExecution, CancellationToken.None))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Worker execution crashed for scan job '{ScanJobId}'.", job.Id);

            if (!await StopHeartbeatAndRefreshJobAsync(
                    job,
                    expectedWorkerInstanceId,
                    heartbeatCts,
                    heartbeatTask,
                    claimedExecution))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = $"EXECUTION_EXCEPTION: {ex.Message}";
            job.CurrentPhase = "Failed";
            job.CompletedAtUtc = DateTime.UtcNow;
            job.LastHeartbeatUtc = DateTime.UtcNow;
            job.JobVersion++;

            if (!await TrySaveTerminalChangesAsync(job, claimedExecution, CancellationToken.None))
            {
                return await BuildCurrentLeaseLostResultAsync(job.Id, CancellationToken.None);
            }

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        finally
        {
            heartbeatCts?.Cancel();
            heartbeatCts?.Dispose();
            executionCts?.Dispose();

            // Deterministic scratch cleanup
            try
            {
                if (scratchDirectory != null && Directory.Exists(scratchDirectory))
                {
                    Directory.Delete(scratchDirectory, recursive: true);
                    _logger.LogInformation(
                        "Worker securely cleaned up scratch directory '{ScratchDirectory}'.",
                        scratchDirectory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clean up scratch directory '{ScratchDirectory}'.", scratchDirectory);
            }
        }
    }

    private async Task<bool> StopHeartbeatAndRefreshJobAsync(
        SecurityScanJob job,
        string? expectedWorkerInstanceId,
        CancellationTokenSource? heartbeatCts,
        Task heartbeatTask,
        bool requireOwnershipRefresh)
    {
        if (heartbeatCts != null)
        {
            heartbeatCts.Cancel();

            try
            {
                await heartbeatTask;
            }
            catch (OperationCanceledException)
            {
                // Expected when terminal state is ready to be persisted.
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Heartbeat loop ended unexpectedly for scan job '{ScanJobId}'.", job.Id);
            }
        }
        else if (!requireOwnershipRefresh)
        {
            return true;
        }

        if (_dbContext is not DbContext efDbContext)
        {
            _logger.LogError(
                "Cannot refresh scan job '{ScanJobId}' after heartbeat because the DbContext does not expose EF tracking.",
                job.Id);
            return false;
        }

        try
        {
            await efDbContext.Entry(job).ReloadAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh scan job '{ScanJobId}' after stopping heartbeat.", job.Id);
            return false;
        }

        return job.Status == SecurityScanJobStatus.Running
            && string.Equals(job.WorkerInstanceId, expectedWorkerInstanceId, StringComparison.Ordinal);
    }

    private async Task<bool> TrySaveTerminalChangesAsync(
        SecurityScanJob job,
        bool claimedExecution,
        CancellationToken ct)
    {
        try
        {
            await _dbContext.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateConcurrencyException) when (claimedExecution)
        {
            _logger.LogWarning(
                "Claimed scan job '{ScanJobId}' lost its execution lease before its terminal state could be persisted.",
                job.Id);
            return false;
        }
    }

    private async Task<ScanExecutionResult> BuildCurrentLeaseLostResultAsync(
        Guid scanJobId,
        CancellationToken ct)
    {
        var currentJob = await _dbContext.SecurityScanJobs
            .AsNoTracking()
            .FirstOrDefaultAsync(job => job.Id == scanJobId, ct);

        if (currentJob == null)
        {
            throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");
        }

        return BuildLeaseLostResult(currentJob);
    }

    private ScanExecutionResult BuildLeaseLostResult(SecurityScanJob job)
    {
        var reason = job.FailureReason ?? "SCAN_JOB_EXECUTION_LEASE_LOST";
        _logger.LogWarning(
            "Scan job '{ScanJobId}' terminal update skipped because execution ownership was lost. CurrentStatus='{Status}', CurrentWorker='{WorkerInstanceId}'.",
            job.Id,
            job.Status,
            job.WorkerInstanceId);

        return new ScanExecutionResult(job.Id, job.Status, null, null, reason, DateTime.UtcNow);
    }
}
