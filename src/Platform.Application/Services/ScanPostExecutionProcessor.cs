using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Orchestrates post-scan processing: result aggregation, historical scan diffing,
/// finding observation tracking, and safe 2-scan confirmed absence resolution.
/// Strict invariant: Orchestrator only. Does not replace Phase 6 Risk Engine or Phase 7 authorization boundary.
/// </summary>
public class ScanPostExecutionProcessor
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ScanJobService _scanJobService;
    private readonly RemediationActionService? _remediationActionService;
    private readonly IOptions<ResponsePolicyOptions>? _responsePolicyOptions;
    private readonly ILogger<ScanPostExecutionProcessor> _logger;

    public ScanPostExecutionProcessor(
        IPlatformDbContext dbContext,
        ScanJobService scanJobService,
        ILogger<ScanPostExecutionProcessor> logger,
        RemediationActionService? remediationActionService = null,
        IOptions<ResponsePolicyOptions>? responsePolicyOptions = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _scanJobService = scanJobService ?? throw new ArgumentNullException(nameof(scanJobService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _remediationActionService = remediationActionService;
        _responsePolicyOptions = responsePolicyOptions;
    }

    /// <summary>
    /// Builds authoritative post-scan summary metrics derived strictly from persisted records and execution receipts.
    /// </summary>
    public async Task<ScanResultSummary> BuildSummaryAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await _scanJobService.GetJobByIdAsync(jobId, ct)
            ?? throw new KeyNotFoundException($"Scan job '{jobId}' not found.");

        ScanExecutionReceipt? receipt = null;
        if (!string.IsNullOrWhiteSpace(job.ExecutionReceiptJson))
        {
            try
            {
                receipt = JsonSerializer.Deserialize<ScanExecutionReceipt>(job.ExecutionReceiptJson);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not deserialize execution receipt for job '{JobId}'.", jobId);
            }
        }

        // Load all observations recorded for this scan job
        var observations = await _dbContext.ScanFindingObservations
            .Include(o => o.Finding)
            .Where(o => o.ScanJobId == jobId)
            .ToListAsync(ct);

        var observedFindings = observations
            .Where(o => o.WasObserved)
            .Select(o => o.Finding)
            .ToList();

        int criticalCount = observedFindings.Count(f => f.Severity == RiskSeverity.Critical);
        int highCount = observedFindings.Count(f => f.Severity == RiskSeverity.High);
        int mediumCount = observedFindings.Count(f => f.Severity == RiskSeverity.Medium);
        int lowCount = observedFindings.Count(f => f.Severity == RiskSeverity.Low);
        int infoCount = observedFindings.Count(f => f.Severity == RiskSeverity.Info);

        int toolsAttempted = receipt?.ToolReceipts?.Count ?? 0;
        int toolsSucceeded = receipt?.ToolReceipts?.Count(t => t.Status == ToolExecutionStatus.Success) ?? 0;
        int toolsFailed = receipt?.ToolReceipts?.Count(t => t.Status == ToolExecutionStatus.Failed) ?? 0;

        long durationMs = receipt?.ToolReceipts?.Sum(t => (long)t.DurationMs) ?? 0;
        long outputBytes = receipt?.ToolReceipts?.Sum(t => t.OutputSizeBytes) ?? 0;

        var findingsByTool = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (receipt?.ToolReceipts != null)
        {
            foreach (var tr in receipt.ToolReceipts)
            {
                findingsByTool[tr.ToolKey] = tr.FindingsCreated + tr.FindingsUpdated;
            }
        }

        var findingsByType = observedFindings
            .GroupBy(f => f.FindingType.ToString())
            .ToDictionary(g => g.Key, g => g.Count());

        return new ScanResultSummary(
            ScanJobId: job.Id,
            TargetId: job.TargetId,
            JobStatus: job.Status,
            FindingsCreated: receipt?.TotalFindingsCreated ?? 0,
            FindingsUpdated: receipt?.TotalFindingsUpdated ?? 0,
            FindingsTotal: observedFindings.Count,
            CriticalCount: criticalCount,
            HighCount: highCount,
            MediumCount: mediumCount,
            LowCount: lowCount,
            InfoCount: infoCount,
            ToolsAttempted: toolsAttempted,
            ToolsSucceeded: toolsSucceeded,
            ToolsFailed: toolsFailed,
            DurationMs: durationMs,
            OutputBytes: outputBytes,
            FindingsByTool: findingsByTool,
            FindingsByType: findingsByType,
            CompletedAtUtc: job.CompletedAtUtc ?? DateTime.UtcNow
        );
    }

    /// <summary>
    /// Calculates differential changes between the current scan and a baseline scan for the same target.
    /// </summary>
    public async Task<ScanDiff> CalculateDiffAsync(Guid currentJobId, Guid? baselineJobId = null, CancellationToken ct = default)
    {
        var currentJob = await _scanJobService.GetJobByIdAsync(currentJobId, ct)
            ?? throw new KeyNotFoundException($"Current scan job '{currentJobId}' not found.");

        SecurityScanJob? baselineJob = null;
        if (baselineJobId.HasValue)
        {
            baselineJob = await _scanJobService.GetJobByIdAsync(baselineJobId.Value, ct)
                ?? throw new KeyNotFoundException($"Baseline scan job '{baselineJobId.Value}' not found.");

            if (baselineJob.TargetId != currentJob.TargetId)
            {
                throw new InvalidOperationException($"Cannot compare scan diff across different targets (Current: '{currentJob.TargetId}', Baseline: '{baselineJob.TargetId}').");
            }
        }
        else if (currentJob.TargetId.HasValue)
        {
            var canonicalProfile = ScanProfileMatrix.CanonicalizeProfile(currentJob.ScanProfile);

            // Find most recent previous terminal successful scan for the exact same target and compatible profile
            baselineJob = await _dbContext.SecurityScanJobs.AsNoTracking()
                .Where(j => j.TargetId == currentJob.TargetId
                         && j.Id != currentJob.Id
                         && (j.Status == SecurityScanJobStatus.Completed || j.Status == SecurityScanJobStatus.CompletedWithWarnings)
                         && j.CreatedAtUtc < currentJob.CreatedAtUtc)
                .OrderByDescending(j => j.CreatedAtUtc)
                .FirstOrDefaultAsync(ct);
        }

        // Current scan observations
        var currentObservations = await _dbContext.ScanFindingObservations
            .Include(o => o.Finding)
            .Where(o => o.ScanJobId == currentJobId)
            .ToListAsync(ct);

        var currentObservedFindingIds = currentObservations
            .Where(o => o.WasObserved)
            .Select(o => o.FindingId)
            .ToHashSet();

        // Baseline observations
        var baselineObservedFindingIds = new HashSet<Guid>();
        if (baselineJob != null)
        {
            var baselineObs = await _dbContext.ScanFindingObservations
                .Where(o => o.ScanJobId == baselineJob.Id && o.WasObserved)
                .Select(o => o.FindingId)
                .ToListAsync(ct);

            baselineObservedFindingIds = baselineObs.ToHashSet();
        }

        // Target's all active and resolved findings
        var allTargetFindings = await _dbContext.SecurityFindings
            .Where(f => f.RepositoryId == currentJob.RepositoryId)
            .ToListAsync(ct);

        var newFindings = new List<ScanFindingDiffItem>();
        var persistentFindings = new List<ScanFindingDiffItem>();
        var notObservedFindings = new List<ScanFindingDiffItem>();
        var resolvedFindings = new List<ScanFindingDiffItem>();

        foreach (var observation in currentObservations)
        {
            var finding = observation.Finding;
            if (finding == null) continue;

            int consecutiveAbsences = await GetConsecutiveAbsentScansCountAsync(finding.Id, currentJob.TargetId, currentJob.ScanProfile, ct);

            if (observation.WasObserved)
            {
                if (baselineJob != null && baselineObservedFindingIds.Contains(finding.Id))
                {
                    persistentFindings.Add(MapToDiffItem(finding, ScanFindingDiffStatus.Persistent, observation.ObservedAtUtc, 0, observation.FullCoverageConfirmed));
                }
                else
                {
                    newFindings.Add(MapToDiffItem(finding, ScanFindingDiffStatus.New, observation.ObservedAtUtc, 0, observation.FullCoverageConfirmed));
                }
            }
            else
            {
                if (finding.Status == FindingStatus.Resolved)
                {
                    resolvedFindings.Add(MapToDiffItem(finding, ScanFindingDiffStatus.Resolved, null, consecutiveAbsences, observation.FullCoverageConfirmed));
                }
                else
                {
                    notObservedFindings.Add(MapToDiffItem(finding, ScanFindingDiffStatus.NotObserved, null, consecutiveAbsences, observation.FullCoverageConfirmed));
                }
            }
        }

        return new ScanDiff(
            CurrentScanJobId: currentJob.Id,
            BaselineScanJobId: baselineJob?.Id,
            NewFindings: newFindings,
            PersistentFindings: persistentFindings,
            NotObservedFindings: notObservedFindings,
            ResolvedFindings: resolvedFindings,
            GeneratedAtUtc: DateTime.UtcNow
        );
    }

    /// <summary>
    /// Processes post-scan finding observations, evaluates consecutive absent scans for auto-resolution,
    /// and safely proposes Phase 7 remediation actions for Critical/High findings.
    /// </summary>
    public async Task ProcessPostScanLifecycleAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await _dbContext.SecurityScanJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job == null)
        {
            _logger.LogWarning("Scan job '{JobId}' not found for post-execution processing.", jobId);
            return;
        }

        if (job.Status is not (SecurityScanJobStatus.Completed or SecurityScanJobStatus.CompletedWithWarnings))
        {
            _logger.LogInformation("Scan job '{JobId}' status is '{Status}'. Post-execution lifecycle skipped.", jobId, job.Status);
            return;
        }

        ScanExecutionReceipt? receipt = null;
        if (!string.IsNullOrWhiteSpace(job.ExecutionReceiptJson))
        {
            try
            {
                receipt = JsonSerializer.Deserialize<ScanExecutionReceipt>(job.ExecutionReceiptJson);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse receipt for job '{JobId}'.", jobId);
            }
        }

        // 1. Determine Full Coverage Confirmation
        bool isFullCoverage = DetermineFullCoverage(job, receipt);
        string toolCoverageHash = ComputeToolCoverageHash(receipt);

        _logger.LogInformation("Scan job '{JobId}' post-processing: FullCoverage={FullCoverage}, CoverageHash={Hash}.",
            jobId, isFullCoverage, toolCoverageHash);

        // 2. Identify Findings Observed in Current Scan
        // Findings associated with this repository that were updated/observed during this scan window
        var scanObservedFindings = await _dbContext.SecurityFindings
            .Where(f => f.RepositoryId == job.RepositoryId
                     && f.LastObservedAtUtc >= (job.StartedAtUtc ?? job.CreatedAtUtc))
            .ToListAsync(ct);

        var observedFindingIds = scanObservedFindings.Select(f => f.Id).ToHashSet();

        // 3. Load all open findings for this target to check for unobserved items
        var allTargetOpenFindings = await _dbContext.SecurityFindings
            .Where(f => f.RepositoryId == job.RepositoryId && f.Status == FindingStatus.Open)
            .ToListAsync(ct);

        var now = DateTime.UtcNow;

        // 4. Record Observations for Observed Findings
        foreach (var finding in scanObservedFindings)
        {
            var existingObs = await _dbContext.ScanFindingObservations
                .FirstOrDefaultAsync(o => o.FindingId == finding.Id && o.ScanJobId == jobId, ct);

            if (existingObs == null)
            {
                _dbContext.ScanFindingObservations.Add(new ScanFindingObservation
                {
                    Id = Guid.NewGuid(),
                    FindingId = finding.Id,
                    ScanJobId = jobId,
                    ObservedAtUtc = now,
                    WasObserved = true,
                    FullCoverageConfirmed = isFullCoverage,
                    ToolCoverageHash = toolCoverageHash
                });
            }

            // Reappearance rule: If previously resolved finding is observed again, re-open it
            if (finding.Status == FindingStatus.Resolved)
            {
                _logger.LogInformation("Finding '{FindingId}' ({Fingerprint}) previously resolved has reappeared in scan '{JobId}'. Reopening finding.",
                    finding.Id, finding.FindingFingerprint, jobId);

                finding.Status = FindingStatus.Open;
                finding.ResolvedAtUtc = null;
                finding.ResolvedByUserId = null;
                finding.ResolutionReason = null;
                finding.LifecycleVersion++;

                _dbContext.AuditEvents.Add(new AuditEvent
                {
                    Id = Guid.NewGuid(),
                    EventCode = AuditEventCode.FindingStatusChanged,
                    UserId = job.RequestedByUserId,
                    CorrelationId = job.CorrelationId,
                    ResourceType = "SecurityFinding",
                    ResourceId = finding.Id.ToString(),
                    CreatedAtUtc = now,
                    Metadata = $"{{\"FindingId\":\"{finding.Id}\",\"PreviousStatus\":\"Resolved\",\"NewStatus\":\"Open\",\"Reason\":\"Reappeared in scan {job.Id}\"}}"
                });
            }
        }

        // 5. Record Observations & Evaluate Resolution for Unobserved Findings
        foreach (var finding in allTargetOpenFindings)
        {
            if (observedFindingIds.Contains(finding.Id))
                continue; // Already processed as observed

            var existingObs = await _dbContext.ScanFindingObservations
                .FirstOrDefaultAsync(o => o.FindingId == finding.Id && o.ScanJobId == jobId, ct);

            if (existingObs == null)
            {
                _dbContext.ScanFindingObservations.Add(new ScanFindingObservation
                {
                    Id = Guid.NewGuid(),
                    FindingId = finding.Id,
                    ScanJobId = jobId,
                    ObservedAtUtc = now,
                    WasObserved = false,
                    FullCoverageConfirmed = isFullCoverage,
                    ToolCoverageHash = toolCoverageHash
                });
            }

            // Only advance resolution counter if this scan had full coverage
            if (isFullCoverage)
            {
                // Count consecutive absent scans with full coverage on the same target and compatible profile
                int consecutiveAbsent = await GetConsecutiveAbsentScansCountAsync(finding.Id, job.TargetId, job.ScanProfile, ct);
                // Current scan adds 1
                consecutiveAbsent += 1;

                if (consecutiveAbsent >= 2)
                {
                    _logger.LogInformation("Finding '{FindingId}' absent across {Count} consecutive full-coverage scans for target '{TargetId}'. Resolving finding.",
                        finding.Id, consecutiveAbsent, job.TargetId);

                    finding.Status = FindingStatus.Resolved;
                    finding.ResolvedAtUtc = now;
                    finding.ResolutionReason = "ConfirmedAbsenceAcrossConsecutiveScans";
                    finding.LifecycleVersion++;

                    _dbContext.AuditEvents.Add(new AuditEvent
                    {
                        Id = Guid.NewGuid(),
                        EventCode = AuditEventCode.FindingStatusChanged,
                        UserId = job.RequestedByUserId,
                        CorrelationId = job.CorrelationId,
                        ResourceType = "SecurityFinding",
                        ResourceId = finding.Id.ToString(),
                        CreatedAtUtc = now,
                        Metadata = $"{{\"FindingId\":\"{finding.Id}\",\"PreviousStatus\":\"Open\",\"NewStatus\":\"Resolved\",\"Reason\":\"Confirmed absence across {consecutiveAbsent} consecutive scans.\"}}"
                    });
                }
                else
                {
                    _logger.LogDebug("Finding '{FindingId}' not observed in scan '{JobId}' (Absence count: {Count}/2). Remaining Open.",
                        finding.Id, jobId, consecutiveAbsent);
                }
            }
            else
            {
                _logger.LogDebug("Scan '{JobId}' lacked full capability coverage. Absence of finding '{FindingId}' will not count toward resolution.",
                    jobId, finding.Id);
            }
        }

        // 6. Idempotent Phase 7 Remediation Proposals for Critical / High Findings
        if (_responsePolicyOptions?.Value?.Enabled == true && _remediationActionService != null)
        {
            foreach (var finding in scanObservedFindings)
            {
                if (finding.Severity is RiskSeverity.Critical or RiskSeverity.High)
                {
                    try
                    {
                        await _remediationActionService.EvaluateAndRecommendActionAsync(finding.Id, ct: ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to evaluate remediation proposal for finding '{FindingId}'.", finding.Id);
                    }
                }
            }
        }

        await _dbContext.SaveChangesAsync(ct);
        _logger.LogInformation("Post-scan lifecycle processing complete for job '{JobId}'.", jobId);
    }

    private static bool DetermineFullCoverage(SecurityScanJob job, ScanExecutionReceipt? receipt)
    {
        if (job.Status is not (SecurityScanJobStatus.Completed or SecurityScanJobStatus.CompletedWithWarnings))
            return false;

        if (receipt == null || receipt.ToolReceipts == null || !receipt.ToolReceipts.Any())
            return false;

        // Any fatal sandbox failure immediately voids full coverage
        if (receipt.ToolReceipts.Any(t => t.FailureClassification == ToolFailureClassification.SecurityBoundary))
            return false;

        var requiredCaps = ScanJobService.GetRequiredCapabilitiesForProfile(job.ScanProfile);
        var successfulTools = receipt.ToolReceipts
            .Where(t => t.Status == ToolExecutionStatus.Success && t.FailureClassification == ToolFailureClassification.None)
            .Select(t => t.ToolKey.ToLowerInvariant())
            .ToHashSet();

        // Check each required capability has at least one successful tool
        foreach (var cap in requiredCaps)
        {
            var capableTools = ScanProfileMatrix.WellKnownToolCapabilities
                .Where(kvp => kvp.Value.Contains(cap))
                .Select(kvp => kvp.Key.ToLowerInvariant());

            if (!capableTools.Any(t => successfulTools.Contains(t)))
            {
                return false;
            }
        }

        return true;
    }

    private static string ComputeToolCoverageHash(ScanExecutionReceipt? receipt)
    {
        if (receipt?.ToolReceipts == null || !receipt.ToolReceipts.Any())
            return "EMPTY_COVERAGE";

        var payload = string.Join(";", receipt.ToolReceipts
            .OrderBy(t => t.ToolKey, StringComparer.OrdinalIgnoreCase)
            .Select(t => $"{t.ToolKey}:{t.Version}:{t.Status}:{t.FailureClassification}"));

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
    }

    private async Task<int> GetConsecutiveAbsentScansCountAsync(
        Guid findingId,
        Guid? targetId,
        SecurityScanProfileType profile,
        CancellationToken ct)
    {
        if (!targetId.HasValue) return 0;

        var canonicalProfile = ScanProfileMatrix.CanonicalizeProfile(profile);

        // Query historical observations for the same target in reverse chronological order
        var historicalObs = await _dbContext.ScanFindingObservations
            .Include(o => o.ScanJob)
            .Where(o => o.FindingId == findingId
                     && o.ScanJob.TargetId == targetId)
            .OrderByDescending(o => o.ObservedAtUtc)
            .ToListAsync(ct);

        int count = 0;
        foreach (var obs in historicalObs)
        {
            if (obs.ScanJob == null || ScanProfileMatrix.CanonicalizeProfile(obs.ScanJob.ScanProfile) != canonicalProfile)
                continue;

            if (obs.WasObserved)
            {
                break; // Found an observation where the finding was present; streak ends
            }

            if (obs.FullCoverageConfirmed)
            {
                count++;
            }
            else
            {
                break; // Incomplete scan breaks the consecutive full-coverage streak
            }
        }

        return count;
    }

    private static ScanFindingDiffItem MapToDiffItem(
        SecurityFinding finding,
        ScanFindingDiffStatus status,
        DateTime? currentObservedAtUtc,
        int consecutiveAbsentScans,
        bool fullCoverageConfirmed)
    {
        return new ScanFindingDiffItem(
            FindingFingerprint: finding.FindingFingerprint,
            Status: status,
            Severity: finding.Severity,
            FindingType: finding.FindingType.ToString(),
            Title: finding.Title,
            CanonicalTarget: finding.Description,
            PreviousObservedAtUtc: finding.FirstObservedAtUtc,
            CurrentObservedAtUtc: currentObservedAtUtc,
            ConsecutiveAbsentScans: consecutiveAbsentScans,
            FullCoverageConfirmed: fullCoverageConfirmed
        );
    }
}
