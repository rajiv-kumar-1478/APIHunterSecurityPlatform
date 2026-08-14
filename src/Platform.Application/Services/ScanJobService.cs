using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Common;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class ScanJobService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ICurrentUserContext _currentUserContext;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly ILogger<ScanJobService> _logger;

    public ScanJobService(
        IPlatformDbContext dbContext,
        ICurrentUserContext currentUserContext,
        ScanToolRegistryService toolRegistryService,
        ILogger<ScanJobService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _currentUserContext = currentUserContext ?? throw new ArgumentNullException(nameof(currentUserContext));
        _toolRegistryService = toolRegistryService ?? throw new ArgumentNullException(nameof(toolRegistryService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<SecurityScanJob> CreateScanJobAsync(CreateScanJobRequest request, CancellationToken ct = default)
    {
        var userId = _currentUserContext.UserId ?? throw new InvalidOperationException("User must be authenticated to create a scan job.");

        if (string.IsNullOrWhiteSpace(request.TargetUrl))
        {
            throw new ArgumentException("Target URL cannot be empty.", nameof(request.TargetUrl));
        }

        // Validate scope & target authorization
        await ValidateTargetScopeAsync(request.TargetId, request.TargetUrl, ct);

        // Validate required capabilities for profile
        var requiredCaps = GetRequiredCapabilitiesForProfile(request.ScanProfile);
        var availableTools = await _toolRegistryService.GetToolsForCapabilitiesAsync(requiredCaps, ct);

        var missingRequiredTools = availableTools
            .Where(t => t.Required && t.HealthStatus != ToolHealthStatus.Healthy)
            .ToList();

        if (missingRequiredTools.Any())
        {
            var missingKeys = string.Join(", ", missingRequiredTools.Select(t => t.ToolKey));
            _logger.LogWarning("Cannot queue scan job for '{TargetUrl}': required tools missing/unhealthy ({MissingTools}).", request.TargetUrl, missingKeys);
            throw new InvalidOperationException($"Scan job blocked: required tools are missing or unhealthy: {missingKeys}");
        }

        var scanJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = request.RepositoryId,
            TargetId = request.TargetId,
            TargetUrl = request.TargetUrl.Trim(),
            ScanProfile = request.ScanProfile,
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = userId,
            ProviderKey = request.ProviderKey ?? "bughunter",
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = DateTime.UtcNow,
            JobVersion = 1
        };

        _dbContext.SecurityScanJobs.Add(scanJob);

        // Audit Event
        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            EventCode = AuditEventCode.ScanJobCreated,
            UserId = userId,
            CorrelationId = scanJob.CorrelationId,
            ResourceType = "SecurityScanJob",
            ResourceId = scanJob.Id.ToString(),
            CreatedAtUtc = DateTime.UtcNow,
            Metadata = $"{{\"ScanJobId\":\"{scanJob.Id}\",\"TargetUrl\":\"{scanJob.TargetUrl}\",\"Profile\":\"{scanJob.ScanProfile}\"}}"
        });

        await _dbContext.SaveChangesAsync(ct);
        _logger.LogInformation("Security scan job '{ScanJobId}' successfully created for '{TargetUrl}'.", scanJob.Id, scanJob.TargetUrl);

        return scanJob;
    }

    public async Task<SecurityScanJob?> GetJobByIdAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs
            .Include(j => j.Target)
            .Include(j => j.Repository)
            .FirstOrDefaultAsync(j => j.Id == jobId, ct);

        if (job != null)
        {
            EnsureUserAuthorizedForJob(job);
        }

        return job;
    }

    public async Task<ScanJobDetailDto?> GetJobDetailAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs
            .Include(j => j.Target)
            .Include(j => j.Repository)
            .FirstOrDefaultAsync(j => j.Id == jobId, ct);

        if (job == null) return null;

        EnsureUserAuthorizedForJob(job);
        return MapToDetailDto(job);
    }

    public async Task<ScanExecutionReceipt?> GetJobReceiptAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.AsNoTracking()
            .FirstOrDefaultAsync(j => j.Id == jobId, ct);

        if (job == null) return null;

        EnsureUserAuthorizedForJob(job);

        if (string.IsNullOrWhiteSpace(job.ExecutionReceiptJson))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<ScanExecutionReceipt>(job.ExecutionReceiptJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to deserialize execution receipt JSON for scan job '{JobId}'.", jobId);
            return null;
        }
    }

    public async Task<IReadOnlyList<SecurityScanJob>> ListJobsAsync(int page = 1, int pageSize = 50, SecurityScanJobStatus? statusFilter = null, CancellationToken ct = default)
    {
        var query = _dbContext.SecurityScanJobs.AsNoTracking();

        if (!_currentUserContext.IsPlatformAdmin)
        {
            var userId = _currentUserContext.UserId ?? Guid.Empty;
            query = query.Where(j => j.RequestedByUserId == userId);
        }

        if (statusFilter.HasValue)
        {
            query = query.Where(j => j.Status == statusFilter.Value);
        }

        return await query
            .OrderByDescending(j => j.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<ScanJobDetailDto>> ListJobsDetailAsync(int page = 1, int pageSize = 50, SecurityScanJobStatus? statusFilter = null, CancellationToken ct = default)
    {
        var query = _dbContext.SecurityScanJobs
            .Include(j => j.Target)
            .Include(j => j.Repository)
            .AsNoTracking();

        if (!_currentUserContext.IsPlatformAdmin)
        {
            var userId = _currentUserContext.UserId ?? Guid.Empty;
            query = query.Where(j => j.RequestedByUserId == userId);
        }

        if (statusFilter.HasValue)
        {
            query = query.Where(j => j.Status == statusFilter.Value);
        }

        var jobs = await query
            .OrderByDescending(j => j.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return jobs.Select(MapToDetailDto).ToList();
    }

    public async Task<SecurityScanJob> CancelScanJobAsync(Guid jobId, string reason, int expectedVersion, CancellationToken ct = default)
    {
        var userId = _currentUserContext.UserId ?? throw new InvalidOperationException("User must be authenticated.");

        var job = await _dbContext.SecurityScanJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
            ?? throw new KeyNotFoundException($"Scan job '{jobId}' not found.");

        EnsureUserAuthorizedForJob(job);

        if (job.JobVersion != expectedVersion)
        {
            throw new DbUpdateConcurrencyException($"Concurrency conflict: scan job version is {job.JobVersion}, expected {expectedVersion}.");
        }

        if (job.Status is SecurityScanJobStatus.Completed or SecurityScanJobStatus.CompletedWithWarnings or SecurityScanJobStatus.Failed or SecurityScanJobStatus.Cancelled)
        {
            throw new InvalidOperationException($"Cannot cancel scan job in terminal status '{job.Status}'.");
        }

        job.Status = SecurityScanJobStatus.Cancelled;
        job.CancelledAtUtc = DateTime.UtcNow;
        job.FailureReason = $"Cancelled by user: {reason}";
        job.CurrentPhase = "Cancelled";
        job.JobVersion++;

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            EventCode = AuditEventCode.ScanJobCancelled,
            UserId = userId,
            CorrelationId = job.CorrelationId,
            ResourceType = "SecurityScanJob",
            ResourceId = job.Id.ToString(),
            CreatedAtUtc = DateTime.UtcNow,
            Metadata = $"{{\"ScanJobId\":\"{jobId}\",\"Reason\":\"{reason}\"}}"
        });

        await _dbContext.SaveChangesAsync(ct);
        return job;
    }

    public async Task<SecurityScanJob> RetryScanJobAsync(Guid jobId, CancellationToken ct = default)
    {
        var userId = _currentUserContext.UserId ?? throw new InvalidOperationException("User must be authenticated to retry a scan job.");

        var originalJob = await _dbContext.SecurityScanJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
            ?? throw new KeyNotFoundException($"Scan job '{jobId}' not found.");

        EnsureUserAuthorizedForJob(originalJob);

        if (originalJob.Status is not (SecurityScanJobStatus.Failed or SecurityScanJobStatus.Cancelled or SecurityScanJobStatus.CompletedWithWarnings))
        {
            throw new InvalidOperationException($"Only failed, cancelled, or completed-with-warnings scan jobs can be retried. Current status is '{originalJob.Status}'.");
        }

        // Re-validate scope & target authorization
        await ValidateTargetScopeAsync(originalJob.TargetId, originalJob.TargetUrl, ct);

        // Validate required capabilities for profile
        var requiredCaps = GetRequiredCapabilitiesForProfile(originalJob.ScanProfile);
        var availableTools = await _toolRegistryService.GetToolsForCapabilitiesAsync(requiredCaps, ct);

        var missingRequiredTools = availableTools
            .Where(t => t.Required && t.HealthStatus != ToolHealthStatus.Healthy)
            .ToList();

        if (missingRequiredTools.Any())
        {
            var missingKeys = string.Join(", ", missingRequiredTools.Select(t => t.ToolKey));
            throw new InvalidOperationException($"Retry blocked: required tools are missing or unhealthy: {missingKeys}");
        }

        var retriedJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = originalJob.RepositoryId,
            TargetId = originalJob.TargetId,
            TargetUrl = originalJob.TargetUrl,
            ScanProfile = originalJob.ScanProfile,
            Status = SecurityScanJobStatus.Queued,
            RequestedByUserId = userId,
            ProviderKey = originalJob.ProviderKey,
            CorrelationId = originalJob.CorrelationId,
            RetryOfJobId = originalJob.Id,
            CreatedAtUtc = DateTime.UtcNow,
            JobVersion = 1
        };

        _dbContext.SecurityScanJobs.Add(retriedJob);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            EventCode = AuditEventCode.ScanJobRetried,
            UserId = userId,
            CorrelationId = retriedJob.CorrelationId,
            ResourceType = "SecurityScanJob",
            ResourceId = retriedJob.Id.ToString(),
            CreatedAtUtc = DateTime.UtcNow,
            Metadata = $"{{\"OriginalJobId\":\"{originalJob.Id}\",\"NewJobId\":\"{retriedJob.Id}\",\"TargetUrl\":\"{retriedJob.TargetUrl}\"}}"
        });

        await _dbContext.SaveChangesAsync(ct);
        _logger.LogInformation("Security scan job '{OriginalJobId}' retried as new job '{NewJobId}'.", originalJob.Id, retriedJob.Id);

        return retriedJob;
    }

    private void EnsureUserAuthorizedForJob(SecurityScanJob job)
    {
        if (_currentUserContext.IsPlatformAdmin) return;

        var currentUserId = _currentUserContext.UserId;
        if (!currentUserId.HasValue || job.RequestedByUserId != currentUserId.Value)
        {
            _logger.LogWarning("Access denied for user '{UserId}' to scan job '{JobId}' owned by '{OwnerId}'.", currentUserId, job.Id, job.RequestedByUserId);
            throw new UnauthorizedAccessException("You are not authorized to access or modify this security scan job.");
        }
    }

    private static ScanJobDetailDto MapToDetailDto(SecurityScanJob job)
    {
        ScanExecutionReceipt? receipt = null;
        if (!string.IsNullOrWhiteSpace(job.ExecutionReceiptJson))
        {
            try
            {
                receipt = JsonSerializer.Deserialize<ScanExecutionReceipt>(job.ExecutionReceiptJson);
            }
            catch
            {
                // Ignore deserialization error
            }
        }

        return new ScanJobDetailDto(
            Id: job.Id,
            RepositoryId: job.RepositoryId,
            RepositoryName: job.Repository?.Name,
            TargetId: job.TargetId,
            TargetName: job.Target?.Name,
            TargetUrl: job.TargetUrl,
            ScanProfile: job.ScanProfile,
            Status: job.Status,
            ProviderKey: job.ProviderKey,
            CorrelationId: job.CorrelationId,
            ProgressPercentage: job.ProgressPercentage,
            CurrentPhase: job.CurrentPhase,
            CurrentTool: job.CurrentTool,
            TotalFindingsCount: job.TotalFindingsCount,
            CreatedAtUtc: job.CreatedAtUtc,
            StartedAtUtc: job.StartedAtUtc,
            CompletedAtUtc: job.CompletedAtUtc,
            CancelledAtUtc: job.CancelledAtUtc,
            FailureReason: job.FailureReason,
            RetryOfJobId: job.RetryOfJobId,
            Version: job.JobVersion,
            ExecutionReceipt: receipt
        );
    }

    private async Task ValidateTargetScopeAsync(Guid? targetId, string targetUrl, CancellationToken ct)
    {
        if (targetId.HasValue)
        {
            var target = await _dbContext.SecurityTargets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == targetId.Value, ct);
            if (target == null)
            {
                throw new InvalidOperationException($"Target with ID '{targetId.Value}' does not exist.");
            }

            if (!target.Enabled)
            {
                throw new InvalidOperationException($"Security target '{target.Name}' is disabled.");
            }
        }
        else
        {
            // Fail-closed target scope validation
            var registeredTargets = await _dbContext.SecurityTargets.AsNoTracking().Where(t => t.Enabled).ToListAsync(ct);
            if (!registeredTargets.Any())
            {
                _logger.LogWarning("Target scope validation rejected for '{TargetUrl}': zero authorized security targets are configured in the platform.", targetUrl);
                throw new InvalidOperationException($"Target URL '{targetUrl}' is out of scope. No authorized security targets are currently configured in the platform.");
            }

            var uri = new Uri(targetUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? targetUrl : $"https://{targetUrl}");
            var host = uri.Host.ToLowerInvariant();

            var isAuthorized = registeredTargets.Any(t =>
            {
                if (string.IsNullOrWhiteSpace(t.BaseUrl)) return false;
                try
                {
                    var targetUri = new Uri(t.BaseUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? t.BaseUrl : $"https://{t.BaseUrl}");
                    var targetHost = targetUri.Host.ToLowerInvariant();

                    return host.Equals(targetHost, StringComparison.OrdinalIgnoreCase) ||
                           host.EndsWith("." + targetHost, StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    return false;
                }
            });

            if (!isAuthorized)
            {
                _logger.LogWarning("Target URL '{TargetUrl}' does not match any authorized security target domain.", targetUrl);
                throw new InvalidOperationException($"Target URL '{targetUrl}' is out of scope. Scans are permitted only against authorized security targets.");
            }
        }
    }

    public static IReadOnlyList<ToolCapability> GetRequiredCapabilitiesForProfile(SecurityScanProfileType profile) => profile switch
    {
        SecurityScanProfileType.Recon => new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing },
        SecurityScanProfileType.WebAssessment => new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
        SecurityScanProfileType.FullAssessment => new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning, ToolCapability.AiAssistedHunting, ToolCapability.ReportGeneration },
        _ => new[] { ToolCapability.HttpProbing }
    };
}
