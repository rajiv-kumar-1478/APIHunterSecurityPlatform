using System;
using System.Collections.Generic;
using System.Linq;
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
        _dbContext = dbContext;
        _currentUserContext = currentUserContext;
        _toolRegistryService = toolRegistryService;
        _logger = logger;
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
            Version = 1
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
        return await _dbContext.SecurityScanJobs
            .Include(j => j.Target)
            .Include(j => j.Repository)
            .FirstOrDefaultAsync(j => j.Id == jobId, ct);
    }

    public async Task<IReadOnlyList<SecurityScanJob>> ListJobsAsync(int page = 1, int pageSize = 50, SecurityScanJobStatus? statusFilter = null, CancellationToken ct = default)
    {
        var query = _dbContext.SecurityScanJobs.AsNoTracking();

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

    public async Task<SecurityScanJob> CancelScanJobAsync(Guid jobId, string reason, int expectedVersion, CancellationToken ct = default)
    {
        var userId = _currentUserContext.UserId ?? throw new InvalidOperationException("User must be authenticated.");

        var job = await _dbContext.SecurityScanJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
            ?? throw new KeyNotFoundException($"Scan job '{jobId}' not found.");

        if (job.Version != expectedVersion)
        {
            throw new DbUpdateConcurrencyException($"Concurrency conflict: scan job version is {job.Version}, expected {expectedVersion}.");
        }

        if (job.Status is SecurityScanJobStatus.Completed or SecurityScanJobStatus.Failed or SecurityScanJobStatus.Cancelled)
        {
            throw new InvalidOperationException($"Cannot cancel scan job in status '{job.Status}'.");
        }

        job.Status = SecurityScanJobStatus.Cancelled;
        job.CancelledAtUtc = DateTime.UtcNow;
        job.FailureReason = $"Cancelled by user: {reason}";
        job.Version++;

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
            // Verify if target URL matches any registered authorized target
            var uri = new Uri(targetUrl.StartsWith("http") ? targetUrl : $"https://{targetUrl}");
            var host = uri.Host.ToLowerInvariant();

            var registeredTargets = await _dbContext.SecurityTargets.AsNoTracking().Where(t => t.Enabled).ToListAsync(ct);
            var isAuthorized = registeredTargets.Any(t =>
                t.BaseUrl.Contains(host, StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith(t.BaseUrl.Replace("https://", "").Replace("http://", "").TrimEnd('/'), StringComparison.OrdinalIgnoreCase));

            if (!isAuthorized && registeredTargets.Any())
            {
                _logger.LogWarning("Scope authorization rejected for target URL '{TargetUrl}': host '{Host}' is not registered under authorized security targets.", targetUrl, host);
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
