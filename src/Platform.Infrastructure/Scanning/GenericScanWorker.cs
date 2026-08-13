using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class GenericScanWorker : IScanWorker
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IScanProviderSecretStore _secretStore;
    private readonly IScanProvider _scanProvider;
    private readonly ILogger<GenericScanWorker> _logger;

    public GenericScanWorker(
        IPlatformDbContext dbContext,
        IScanProviderSecretStore secretStore,
        IScanProvider scanProvider,
        ILogger<GenericScanWorker> logger)
    {
        _dbContext = dbContext;
        _secretStore = secretStore;
        _scanProvider = scanProvider;
        _logger = logger;
    }

    public async Task<ScanExecutionResult> ExecuteScanJobAsync(Guid scanJobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.FindAsync(new object[] { scanJobId }, ct);
        if (job == null)
        {
            throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");
        }

        var scratchDirectory = Path.Combine(Path.GetTempPath(), "scans", scanJobId.ToString("N"));
        Directory.CreateDirectory(scratchDirectory);

        _logger.LogInformation("Worker allocated scratch directory '{ScratchDirectory}' for job '{ScanJobId}'.", scratchDirectory, scanJobId);

        using ProviderSecretLease secretLease = await _secretStore.AcquireLeaseAsync(job.ProviderKey, ct);

        try
        {
            var startResult = await _scanProvider.StartAsync(new ScanExecutionRequest(
                ScanJobId: job.Id,
                TargetUrl: job.TargetUrl,
                Profile: job.ScanProfile,
                ProviderKey: job.ProviderKey,
                Parameters: new System.Collections.Generic.Dictionary<string, string>(),
                Timeout: TimeSpan.FromMinutes(15)
            ), ct);

            if (!startResult.Success)
            {
                job.Status = SecurityScanJobStatus.Failed;
                job.FailureReason = startResult.ErrorMessage ?? "Provider failed to start scan.";
                job.CompletedAtUtc = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync(ct);

                return new ScanExecutionResult(job.Id, job.Status, null, null, job.FailureReason, DateTime.UtcNow);
            }

            var providerResult = await _scanProvider.GetResultAsync(startResult.ExternalScanId, ct);
            job.Status = providerResult.Status;
            job.CompletedAtUtc = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(ct);

            return new ScanExecutionResult(job.Id, job.Status, startResult.ExternalScanId, providerResult.ArtifactReference, providerResult.Summary, DateTime.UtcNow);
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
