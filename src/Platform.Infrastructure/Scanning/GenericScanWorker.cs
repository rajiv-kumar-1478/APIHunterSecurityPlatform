using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class GenericScanWorker : IScanWorker
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IScanProviderSecretStore _secretStore;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly Func<string, IGenericCliToolAdapter> _cliAdapterFactory;
    private readonly IEgressPolicyEngine _egressPolicyEngine;
    private readonly IScannerRuntimeSandbox? _runtimeSandbox;
    private readonly bool _allowUnsafeProcessFallback;
    private readonly ILogger<GenericScanWorker> _logger;

    public GenericScanWorker(
        IPlatformDbContext dbContext,
        IScanProviderSecretStore secretStore,
        ScanToolRegistryService toolRegistryService,
        Func<string, IGenericCliToolAdapter> cliAdapterFactory,
        IEgressPolicyEngine egressPolicyEngine,
        ILogger<GenericScanWorker> logger,
        IScannerRuntimeSandbox? runtimeSandbox = null,
        bool allowUnsafeProcessFallback = true)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _toolRegistryService = toolRegistryService ?? throw new ArgumentNullException(nameof(toolRegistryService));
        _cliAdapterFactory = cliAdapterFactory ?? throw new ArgumentNullException(nameof(cliAdapterFactory));
        _egressPolicyEngine = egressPolicyEngine ?? throw new ArgumentNullException(nameof(egressPolicyEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _runtimeSandbox = runtimeSandbox;
        _allowUnsafeProcessFallback = allowUnsafeProcessFallback;
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

        // 2. Production Security Check: Require Sandbox unless explicit unsafe fallback is allowed
        if (_runtimeSandbox == null && !_allowUnsafeProcessFallback)
        {
            _logger.LogError("GenericScanWorker rejected job '{ScanJobId}': Production environment requires active IScannerRuntimeSandbox.", scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = "SECURITY_SANDBOX_REQUIRED: Production environment requires an active IScannerRuntimeSandbox.";
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }

        var scratchRoot = Path.Combine(Path.GetTempPath(), "apihunter_scans");
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

                var cliAdapter = _cliAdapterFactory(tool.ToolKey);
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

                var toolResult = _runtimeSandbox != null
                    ? await _runtimeSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDirectory, ct)
                    : await cliAdapter.ExecuteAsync(toolRequest, secretLease, scratchDirectory, ct);
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
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            var summary = $"Executed {toolResults.Count} tools for target '{job.TargetUrl}'.";
            return new ScanExecutionResult(job.Id, job.Status, job.CorrelationId, scratchDirectory, summary, DateTime.UtcNow);
        }
        catch (OperationCanceledException ex)
        {
            _logger.LogWarning(ex, "Scan execution for job '{ScanJobId}' was cancelled.", scanJobId);
            job.Status = SecurityScanJobStatus.Failed;
            job.FailureReason = "CANCELLED: Tool execution cancelled or timed out.";
            job.CompletedAtUtc = DateTime.UtcNow;
            try
            {
                await _dbContext.SaveChangesAsync(CancellationToken.None);
            }
            catch
            {
                // Suppress secondary save errors on cancellation
            }

            return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
        }
        finally
        {
            // Guaranteed Scratch Directory Cleanup
            CleanupScratchDirectorySafely(scratchDirectory);
        }
    }

    private void CleanupScratchDirectorySafely(string directoryPath)
    {
        try
        {
            if (Directory.Exists(directoryPath))
            {
                Directory.Delete(directoryPath, recursive: true);
                _logger.LogInformation("Cleaned up scratch directory '{DirectoryPath}'.", directoryPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to clean up scratch directory '{DirectoryPath}'.", directoryPath);
        }
    }
}
