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
    private readonly ITenantContext _tenantContext;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly ILogger<ScanJobService> _logger;

    public ScanJobService(
        IPlatformDbContext dbContext,
        ICurrentUserContext currentUserContext,
        ITenantContext tenantContext,
        ScanToolRegistryService toolRegistryService,
        ILogger<ScanJobService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _currentUserContext = currentUserContext ?? throw new ArgumentNullException(nameof(currentUserContext));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
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

        if (string.IsNullOrWhiteSpace(request.ProviderKey))
        {
            throw new ArgumentException("A registered scan provider must be selected.", nameof(request.ProviderKey));
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
            TenantId = _tenantContext.TenantId,
            RequestedByUserId = userId,
            ProviderKey = request.ProviderKey.Trim(),
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
        var query = _dbContext.SecurityScanJobs.AsNoTracking()
            .Where(j => j.TenantId == _tenantContext.TenantId);

        if (!_currentUserContext.IsPlatformAdmin)
        {
            var userId = _currentUserContext.UserId
                ?? throw new UnauthorizedAccessException("An authenticated user is required to list scan jobs.");
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
            .AsNoTracking()
            .Where(j => j.TenantId == _tenantContext.TenantId);

        if (!_currentUserContext.IsPlatformAdmin)
        {
            var userId = _currentUserContext.UserId
                ?? throw new UnauthorizedAccessException("An authenticated user is required to list scan jobs.");
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
            TenantId = originalJob.TenantId,
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
        if (job.TenantId != _tenantContext.TenantId)
        {
            _logger.LogWarning(
                "Access denied to scan job '{JobId}' in tenant '{JobTenantId}' from configured tenant '{CurrentTenantId}'.",
                job.Id,
                job.TenantId,
                _tenantContext.TenantId);
            throw new UnauthorizedAccessException("You are not authorized to access or modify this security scan job.");
        }

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

    public async Task ValidateTargetScopeAsync(Guid? targetId, string targetUrl, CancellationToken ct = default)
    {
        if (!TryCreateAbsoluteHttpUri(targetUrl, out var requestedUri))
        {
            throw new InvalidOperationException($"Target URL '{targetUrl}' is invalid. A valid HTTP or HTTPS target is required.");
        }

        List<SecurityTarget> authorizedTargets;
        if (targetId.HasValue)
        {
            var target = await _dbContext.SecurityTargets
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == targetId.Value, ct);

            if (target == null)
            {
                throw new InvalidOperationException($"Target with ID '{targetId.Value}' does not exist.");
            }

            if (!target.Enabled)
            {
                throw new InvalidOperationException($"Security target '{target.Name}' is disabled.");
            }

            authorizedTargets = [target];
        }
        else
        {
            authorizedTargets = await _dbContext.SecurityTargets
                .AsNoTracking()
                .Where(t => t.Enabled)
                .ToListAsync(ct);
        }

        var requestedHost = requestedUri.Host.ToLowerInvariant();
        var isAuthorized = authorizedTargets.Any(target =>
        {
            if (!TryCreateAbsoluteHttpUri(target.BaseUrl, out var authorizedUri))
            {
                return false;
            }

            var authorizedHost = authorizedUri.Host.ToLowerInvariant();
            return requestedHost.Equals(authorizedHost, StringComparison.OrdinalIgnoreCase)
                || requestedHost.EndsWith("." + authorizedHost, StringComparison.OrdinalIgnoreCase);
        });

        if (!isAuthorized && !targetId.HasValue)
        {
            // Also authorize targets registered under CI/CD applications for this tenant
            var registeredApps = await _dbContext.RegisteredApplications
                .AsNoTracking()
                .Where(a => a.Enabled && a.TenantId == _tenantContext.TenantId)
                .ToListAsync(ct);

            isAuthorized = registeredApps.Any(app =>
            {
                if (!TryCreateAbsoluteHttpUri(app.AuthorizedTargetUrl, out var appUri))
                {
                    return false;
                }

                var appHost = appUri.Host.ToLowerInvariant();
                return requestedHost.Equals(appHost, StringComparison.OrdinalIgnoreCase)
                    || requestedHost.EndsWith("." + appHost, StringComparison.OrdinalIgnoreCase);
            });
        }

        if (!isAuthorized)
        {
            _logger.LogWarning(
                "Target URL '{TargetUrl}' does not match the authorized security target scope (TargetId={TargetId}).",
                targetUrl,
                targetId);
            throw new InvalidOperationException(
                $"Target URL '{targetUrl}' is out of scope. Scans are permitted only against an authorized security target domain.");
        }
    }

    private static bool TryCreateAbsoluteHttpUri(string value, out Uri uri)
    {
        var candidate = value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? value
                : $"https://{value}";

        if (Uri.TryCreate(candidate, UriKind.Absolute, out var parsed)
            && (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps)
            && !string.IsNullOrWhiteSpace(parsed.Host))
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }

    public static IReadOnlyList<ToolCapability> GetRequiredCapabilitiesForProfile(SecurityScanProfileType profile) => profile switch
    {
        SecurityScanProfileType.Recon => new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing },
        SecurityScanProfileType.WebAssessment => new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
        SecurityScanProfileType.FullAssessment => new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning, ToolCapability.AiAssistedHunting, ToolCapability.ReportGeneration },
        _ => new[] { ToolCapability.HttpProbing }
    };
}
