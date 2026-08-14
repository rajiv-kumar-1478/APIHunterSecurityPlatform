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
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative service that compiles the single canonical security report model
/// from persisted scan records, summary metrics, diff analysis, and sanitized evidence.
/// </summary>
public class ScanReportBuilderService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ScanJobService _scanJobService;
    private readonly ScanPostExecutionProcessor _postProcessor;
    private readonly ILogger<ScanReportBuilderService> _logger;

    public ScanReportBuilderService(
        IPlatformDbContext dbContext,
        ScanJobService scanJobService,
        ScanPostExecutionProcessor postProcessor,
        ILogger<ScanReportBuilderService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _scanJobService = scanJobService ?? throw new ArgumentNullException(nameof(scanJobService));
        _postProcessor = postProcessor ?? throw new ArgumentNullException(nameof(postProcessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Builds the authoritative canonical security report.
    /// Invariant: All format projections (JSON, SARIF, Markdown, HTML) consume this identical model.
    /// </summary>
    public async Task<CanonicalSecurityReport> BuildCanonicalReportAsync(
        Guid scanJobId,
        Guid? baselineJobId = null,
        CancellationToken ct = default)
    {
        var job = await _scanJobService.GetJobByIdAsync(scanJobId, ct)
            ?? throw new KeyNotFoundException($"Scan job '{scanJobId}' not found.");

        var repository = await _dbContext.Repositories.AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == job.RepositoryId, ct);

        var target = job.TargetId.HasValue
            ? await _dbContext.SecurityTargets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == job.TargetId.Value, ct)
            : null;

        var scanSummary = await _postProcessor.BuildSummaryAsync(scanJobId, ct);
        var scanDiff = await _postProcessor.CalculateDiffAsync(scanJobId, baselineJobId, ct);

        // Deserialized tool receipts
        var toolReceipts = new List<ToolExecutionReceipt>();
        if (!string.IsNullOrWhiteSpace(job.ExecutionReceiptJson))
        {
            try
            {
                var receipt = JsonSerializer.Deserialize<ScanExecutionReceipt>(job.ExecutionReceiptJson);
                if (receipt?.ToolReceipts != null)
                {
                    toolReceipts.AddRange(receipt.ToolReceipts);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to deserialize tool receipts for report of job '{JobId}'.", scanJobId);
            }
        }

        // Observed findings for this job
        var observations = await _dbContext.ScanFindingObservations.AsNoTracking()
            .Include(o => o.Finding)
            .Where(o => o.ScanJobId == scanJobId && o.WasObserved)
            .ToListAsync(ct);

        var findingIds = observations.Select(o => o.FindingId).ToList();

        var evidences = await _dbContext.SecurityFindingEvidences.AsNoTracking()
            .Where(e => findingIds.Contains(e.FindingId))
            .ToListAsync(ct);

        var evidencesByFinding = evidences
            .GroupBy(e => e.FindingId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var remediationActions = await _dbContext.RemediationActions.AsNoTracking()
            .Where(a => findingIds.Contains(a.FindingId))
            .ToListAsync(ct);

        var remediationByFinding = remediationActions
            .GroupBy(a => a.FindingId)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(a => a.CreatedAtUtc).FirstOrDefault());

        var reportFindings = new List<ReportFindingItem>();
        var owaspDistribution = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var cweDistribution = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var obs in observations)
        {
            var finding = obs.Finding;
            if (finding == null) continue;

            evidencesByFinding.TryGetValue(finding.Id, out var findingEvidences);
            remediationByFinding.TryGetValue(finding.Id, out var remediation);

            var sanitizedEvidences = (findingEvidences ?? Enumerable.Empty<SecurityFindingEvidence>())
                .Select(e => new SanitizedEvidenceItem(
                    EvidenceFingerprint: e.EvidenceFingerprint,
                    EvidenceReference: EvidenceSanitizer.SanitizeUrl(e.EvidenceReference ?? string.Empty),
                    SafeEvidenceJson: EvidenceSanitizer.SanitizeEvidence(e.SafeEvidenceJson ?? "{}"),
                    CreatedAtUtc: e.CreatedAtUtc
                ))
                .ToList();

            // Extract CVEs and CWEs from evidence JSON safely
            var cveList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var cweList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            double? cvssScore = null;

            foreach (var ev in sanitizedEvidences)
            {
                try
                {
                    using var doc = JsonDocument.Parse(ev.SafeEvidenceJson);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("cveId", out var cveProp) && cveProp.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(cveProp.GetString()))
                    {
                        cveList.Add(cveProp.GetString()!);
                    }
                    if (root.TryGetProperty("cweId", out var cweProp) && cweProp.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(cweProp.GetString()))
                    {
                        var cwe = cweProp.GetString()!;
                        cweList.Add(cwe);
                        cweDistribution[cwe] = cweDistribution.GetValueOrDefault(cwe) + 1;
                    }
                    if (root.TryGetProperty("cvssScore", out var cvssProp) && cvssProp.TryGetDouble(out var cvss))
                    {
                        cvssScore = Math.Max(cvssScore ?? 0, cvss);
                    }
                }
                catch
                {
                    // Ignore non-json or malformed safe evidence
                }
            }

            var owaspCategory = MapFindingTypeToOwasp(finding.FindingType);
            owaspDistribution[owaspCategory] = owaspDistribution.GetValueOrDefault(owaspCategory) + 1;

            ReportRemediationItem? reportRemediation = null;
            if (remediation != null)
            {
                reportRemediation = new ReportRemediationItem(
                    ActionType: remediation.ActionType,
                    Status: remediation.Status,
                    Title: EvidenceSanitizer.SanitizeEvidence(remediation.Title, 256),
                    Description: EvidenceSanitizer.SanitizeEvidence(remediation.Description ?? string.Empty, 2048),
                    ProviderKey: remediation.ProviderKey ?? "platform",
                    ProviderResourceReference: EvidenceSanitizer.SanitizeEvidence(remediation.ProviderResourceReference ?? string.Empty, 512)
                );
            }

            reportFindings.Add(new ReportFindingItem(
                FindingFingerprint: finding.FindingFingerprint,
                Title: EvidenceSanitizer.SanitizeEvidence(finding.Title, 256),
                Description: EvidenceSanitizer.SanitizeEvidence(finding.Description ?? string.Empty, 2048),
                FindingType: finding.FindingType,
                Severity: finding.Severity,
                RiskScore: finding.RiskScore,
                Confidence: finding.Confidence,
                Status: finding.Status,
                FirstObservedAtUtc: finding.FirstObservedAtUtc,
                LastObservedAtUtc: finding.LastObservedAtUtc,
                CveList: cveList.OrderBy(c => c).ToList(),
                CweList: cweList.OrderBy(c => c).ToList(),
                CvssScore: cvssScore,
                SanitizedEvidences: sanitizedEvidences,
                RecommendedRemediation: reportRemediation
            ));
        }

        // Posture Summary
        int criticalCount = reportFindings.Count(f => f.Severity == RiskSeverity.Critical);
        int highCount = reportFindings.Count(f => f.Severity == RiskSeverity.High);
        int mediumCount = reportFindings.Count(f => f.Severity == RiskSeverity.Medium);
        int lowCount = reportFindings.Count(f => f.Severity == RiskSeverity.Low);
        int infoCount = reportFindings.Count(f => f.Severity == RiskSeverity.Info);

        double aggregateRiskScore = reportFindings.Count > 0 ? reportFindings.Max(f => f.RiskScore) : 0.0;
        RiskSeverity riskRating = aggregateRiskScore switch
        {
            >= 90 => RiskSeverity.Critical,
            >= 70 => RiskSeverity.High,
            >= 40 => RiskSeverity.Medium,
            > 0 => RiskSeverity.Low,
            _ => RiskSeverity.Info
        };

        var postureSummary = new ExecutivePostureSummary(
            AggregateRiskScore: aggregateRiskScore,
            RiskRating: riskRating,
            TotalFindings: reportFindings.Count,
            CriticalCount: criticalCount,
            HighCount: highCount,
            MediumCount: mediumCount,
            LowCount: lowCount,
            InfoCount: infoCount,
            OwaspTop10Distribution: owaspDistribution,
            CweTop25Distribution: cweDistribution
        );

        var generatedAtUtc = DateTime.UtcNow;
        var toolCoverageHash = observations.FirstOrDefault()?.ToolCoverageHash ?? "EMPTY_COVERAGE";

        // Canonical deterministic provenance signature
        var signaturePayload = $"ReportSignatureVersion=v1\nScanJobId={job.Id:D}\nTenantId={job.RequestedByUserId:D}\nTargetId={job.TargetId:D}\nCoverageHash={toolCoverageHash}\nGeneratedAtUtc={generatedAtUtc:O}";
        var provenanceSignature = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signaturePayload))).ToLowerInvariant();

        var metadata = new ReportMetadata(
            ReportId: Guid.NewGuid(),
            SignatureVersion: "v1",
            ScanJobId: job.Id,
            TenantId: job.RequestedByUserId,
            TargetId: job.TargetId,
            RepositoryName: repository?.FullName ?? "Unknown Repository",
            TargetUrl: job.TargetUrl,
            ScanProfile: job.ScanProfile,
            JobStatus: job.Status,
            StartedAtUtc: job.StartedAtUtc,
            CompletedAtUtc: job.CompletedAtUtc,
            GeneratedAtUtc: generatedAtUtc,
            DurationMs: scanSummary.DurationMs,
            ToolCoverageHash: toolCoverageHash,
            ProvenanceSignature: provenanceSignature
        );

        return new CanonicalSecurityReport(
            Metadata: metadata,
            PostureSummary: postureSummary,
            Findings: reportFindings.OrderByDescending(f => f.RiskScore).ThenBy(f => f.Title).ToList(),
            ScanSummary: scanSummary,
            ScanDiff: scanDiff,
            ToolReceipts: toolReceipts
        );
    }

    private static string MapFindingTypeToOwasp(FindingType type) => type switch
    {
        FindingType.ValidatedCredentialExposed => "A07:2021-Identification and Authentication Failures",
        FindingType.UnvalidatedCredentialExposed => "A07:2021-Identification and Authentication Failures",
        FindingType.ExpiredCredentialExposed => "A07:2021-Identification and Authentication Failures",
        FindingType.RevokedCredentialExposed => "A07:2021-Identification and Authentication Failures",
        FindingType.OverprivilegedCredential => "A01:2021-Broken Access Control",
        FindingType.DatabaseExposure => "A05:2021-Security Misconfiguration",
        FindingType.ProductionServiceExposed => "A05:2021-Security Misconfiguration",
        FindingType.HistoricalExposureDetected => "A09:2021-Security Logging and Monitoring Failures",
        _ => "A05:2021-Security Misconfiguration"
    };
}
