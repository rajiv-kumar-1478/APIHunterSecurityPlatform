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
    private readonly ILogger<GenericScanWorker> _logger;

    public GenericScanWorker(
        IPlatformDbContext dbContext,
        IScanProviderSecretStore secretStore,
        ScanToolRegistryService toolRegistryService,
        Func<string, IGenericCliToolAdapter> cliAdapterFactory,
        ILogger<GenericScanWorker> logger)
    {
        _dbContext = dbContext;
        _secretStore = secretStore;
        _toolRegistryService = toolRegistryService;
        _cliAdapterFactory = cliAdapterFactory;
        _logger = logger;
    }

    public async Task<ScanExecutionResult> ExecuteScanJobAsync(Guid scanJobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.FindAsync(new object[] { scanJobId }, ct);
        if (job == null)
        {
            throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");
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

            // Resolve required tool capabilities for scan profile
            var requiredCapabilities = ScanJobService.GetRequiredCapabilitiesForProfile(job.ScanProfile);
            var tools = await _toolRegistryService.GetToolsForCapabilitiesAsync(requiredCapabilities, ct);

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
                    Executable: tool.Executable
                );

                var toolResult = await cliAdapter.ExecuteAsync(toolRequest, secretLease, scratchDirectory, ct);
                toolResults.Add(toolResult);

                if (toolResult.Status == ToolExecutionStatus.TimedOut || toolResult.Status == ToolExecutionStatus.Failed)
                {
                    if (tool.Required)
                    {
                        _logger.LogError("Required tool '{ToolKey}' failed or timed out for job '{ScanJobId}'. Aborting scan.", tool.ToolKey, scanJobId);
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
