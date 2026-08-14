using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Common;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
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
    private readonly ScannerRuntimeOptions _options;
    private readonly ILogger<GenericScanWorker> _logger;

    public GenericScanWorker(
        IPlatformDbContext dbContext,
        IScanProviderSecretStore secretStore,
        ScanToolRegistryService toolRegistryService,
        IEgressPolicyEngine egressPolicyEngine,
        IScannerRuntimeSandbox? runtimeSandbox,
        ILogger<GenericScanWorker> logger,
        ScannerRuntimeOptions? options = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _toolRegistryService = toolRegistryService ?? throw new ArgumentNullException(nameof(toolRegistryService));
        _egressPolicyEngine = egressPolicyEngine ?? throw new ArgumentNullException(nameof(egressPolicyEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _runtimeSandbox = runtimeSandbox;
        _options = options ?? new ScannerRuntimeOptions();
    }

    public async Task<ScanExecutionResult> ExecuteScanJobAsync(Guid scanJobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.FindAsync(new object[] { scanJobId }, ct);
        if (job == null)
        {
            throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");
        }

        // 1. Mandatory Fail-Closed Egress Policy Evaluation
        EgressTarget egressTarget;
        try
        {
            egressTarget = await _egressPolicyEngine.EvaluateAndBuildTargetAsync(job.TargetUrl, TimeSpan.FromMinutes(10), ct);
            _logger.LogInformation("Worker validated target '{TargetUrl}' to canonical host '{CanonicalHost}' with {Count} approved IP(s).",
                job.TargetUrl, egressTarget.CanonicalHost, egressTarget.ApprovedIpAddresses.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fail-closed egress policy evaluation failed for target '{TargetUrl}' (Job: {ScanJobId}).", job.TargetUrl, scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = $"EGRESS_POLICY_UNAVAILABLE: {ex.Message}";
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }

        // 2. Strict Invariant: Active IScannerRuntimeSandbox is required (Fail Closed)
        if (_runtimeSandbox == null)
        {
            _logger.LogError("GenericScanWorker rejected job '{ScanJobId}': Active IScannerRuntimeSandbox is required.", scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = "SECURITY_SANDBOX_REQUIRED: Active IScannerRuntimeSandbox is required.";
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }

        var scratchRoot = _options.PlatformScratchRoot;
        var scratchDirectory = Path.Combine(scratchRoot, scanJobId.ToString("N"));

        GenericCliToolAdapter.ValidateScratchDirectoryPath(scratchDirectory, scratchRoot);
        Directory.CreateDirectory(scratchDirectory);
        GenericCliToolAdapter.VerifyNoReparsePointOrSymlink(scratchDirectory);

        _logger.LogInformation("Worker allocated scratch directory '{ScratchDirectory}' for job '{ScanJobId}'.", scratchDirectory, scanJobId);

        using ProviderSecretLease secretLease = await _secretStore.AcquireLeaseAsync(job.ProviderKey, ct);

        try
        {
            job.Status = SecurityScanJobStatus.Running;
            job.StartedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            // Resolve required tool capabilities and authoritative scanner manifest
            var requiredCapabilities = ScanJobService.GetRequiredCapabilitiesForProfile(job.ScanProfile);
            var tools = await _toolRegistryService.GetToolsForCapabilitiesAsync(requiredCapabilities, ct);
            var authorizedManifestMap = await _toolRegistryService.GetAuthorizedManifestMapAsync(ct);

            var toolResults = new List<ToolExecutionResult>();

            foreach (var tool in tools)
            {
                if (!tool.Enabled || tool.HealthStatus != ToolHealthStatus.Healthy)
                {
                    _logger.LogWarning("Worker skipping disabled or unhealthy tool '{ToolKey}' for job '{ScanJobId}'.", tool.ToolKey, scanJobId);
                    continue;
                }

                var toolRequest = new ToolExecutionRequest(
                    ToolKey: tool.ToolKey,
                    Version: tool.Version,
                    Arguments: new Dictionary<string, string> { ["target"] = job.TargetUrl },
                    ScanJobId: job.Id,
                    Timeout: TimeSpan.FromMinutes(10),
                    Executable: tool.Executable,
                    ContainerImageRepository: tool.ContainerImageRepository,
                    ContainerImageDigest: tool.ContainerImageDigest,
                    AuthorizedManifest: authorizedManifestMap
                );

                // Authoritative execution through sandbox ONLY
                var toolResult = await _runtimeSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDirectory, ct);
                toolResults.Add(toolResult);

                if (toolResult.Status == ToolExecutionStatus.TimedOut || toolResult.Status == ToolExecutionStatus.Failed || toolResult.Status == ToolExecutionStatus.Cancelled)
                {
                    if (tool.Required)
                    {
                        _logger.LogError("Required tool '{ToolKey}' failed, timed out, or was cancelled for job '{ScanJobId}'. Aborting scan.", tool.ToolKey, scanJobId);
                        job.Status = SecurityScanJobStatus.Failed;
                        job.FailureReason = $"Required tool '{tool.ToolKey}' failed: {toolResult.ErrorCode}";
                        job.CompletedAtUtc = DateTime.UtcNow;
                        await _dbContext.SaveChangesAsync(ct);

                        return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
                    }
                }
            }

            job.Status = SecurityScanJobStatus.Completed;
            job.FailureReason = null;
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            _logger.LogInformation("GenericScanWorker completed job '{ScanJobId}' successfully with {Count} tool results.", scanJobId, toolResults.Count);
            return new ScanExecutionResult(job.Id, job.Status, null, null, null, DateTime.UtcNow);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Worker execution cancelled for scan job '{ScanJobId}'.", scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = "SCAN_JOB_CANCELLED";
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(CancellationToken.None);

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Worker execution crashed for scan job '{ScanJobId}'.", scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = $"EXECUTION_EXCEPTION: {ex.Message}";
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(CancellationToken.None);

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        finally
        {
            // Deterministic scratch cleanup
            try
            {
                if (Directory.Exists(scratchDirectory))
                {
                    Directory.Delete(scratchDirectory, recursive: true);
                    _logger.LogInformation("Worker securely cleaned up scratch directory '{ScratchDirectory}'.", scratchDirectory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clean up scratch directory '{ScratchDirectory}'.", scratchDirectory);
            }
        }
    }
}
