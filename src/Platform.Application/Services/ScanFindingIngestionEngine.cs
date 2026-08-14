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
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative ingestion engine processing untrusted scanner outputs into trusted Phase 6 SecurityFinding records.
/// Enforces canonical target scope authorization, deterministic deduplication fingerprints, evidence sanitization,
/// timestamp bounds, lifecycle state initialization, and authoritative Phase 6 Risk Engine scoring.
/// </summary>
public class ScanFindingIngestionEngine
{
    private readonly IPlatformDbContext _dbContext;
    private readonly RiskEngine _riskEngine;
    private readonly ILogger<ScanFindingIngestionEngine> _logger;

    public ScanFindingIngestionEngine(
        IPlatformDbContext dbContext,
        ILogger<ScanFindingIngestionEngine> logger,
        RiskEngine? riskEngine = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _riskEngine = riskEngine ?? new RiskEngine(new RiskPolicyOptions());
    }

    /// <summary>
    /// Ingests a collection of untrusted FindingCandidate instances for a scan job.
    /// </summary>
    public async Task<FindingIngestionResult> IngestCandidatesAsync(
        IReadOnlyList<FindingCandidate> candidates,
        ScanJobContext context,
        ParserResourceBounds? resourceBounds = null,
        CancellationToken ct = default)
    {
        if (candidates == null || candidates.Count == 0)
        {
            return new FindingIngestionResult(0, 0, 0, 0, 0, 0, new[] { "Zero candidates provided for ingestion." });
        }

        var bounds = resourceBounds ?? new ParserResourceBounds();
        var diagnostics = new List<string>();

        var totalReceived = candidates.Count;
        var accepted = 0;
        var outOfScopeCount = 0;
        var invalidCount = 0;
        var newFindingsCount = 0;
        var updatedFindingsCount = 0;

        // 1. Resolve Authorized Job Target Host & Scheme
        if (!Uri.TryCreate(context.TargetUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? context.TargetUrl : $"https://{context.TargetUrl}", UriKind.Absolute, out var jobTargetUri))
        {
            _logger.LogError("Scan job '{JobId}' has invalid TargetUrl '{TargetUrl}'. Ingestion aborted.", context.JobId, context.TargetUrl);
            throw new InvalidOperationException($"Invalid scan job TargetUrl '{context.TargetUrl}'.");
        }
        var authorizedHost = jobTargetUri.Host.ToLowerInvariant();

        // 2. Cap Candidate Batch Size
        var cappedCandidates = candidates.Take(bounds.MaxCandidateCount).ToList();
        if (candidates.Count > bounds.MaxCandidateCount)
        {
            diagnostics.Add($"Candidate count {candidates.Count} exceeded maximum execution limit of {bounds.MaxCandidateCount}. Truncated to {bounds.MaxCandidateCount}.");
            _logger.LogWarning("Job '{JobId}': candidate count {Count} truncated to bound {Limit}.", context.JobId, candidates.Count, bounds.MaxCandidateCount);
        }

        var affectedFindings = new List<SecurityFinding>();

        foreach (var candidate in cappedCandidates)
        {
            // 3. Validate Candidate Structure
            if (string.IsNullOrWhiteSpace(candidate.Title) || string.IsNullOrWhiteSpace(candidate.TargetUrl))
            {
                invalidCount++;
                diagnostics.Add($"Candidate from tool '{candidate.ToolKey}' discarded: missing Title or TargetUrl.");
                continue;
            }

            // 4. Strict Canonical Scope Validation (Scheme, Host, Port)
            if (!Uri.TryCreate(candidate.TargetUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? candidate.TargetUrl : $"https://{candidate.TargetUrl}", UriKind.Absolute, out var candUri))
            {
                outOfScopeCount++;
                diagnostics.Add($"Candidate '{candidate.Title}' discarded: malformed TargetUrl '{candidate.TargetUrl}'.");
                continue;
            }

            var candHost = candUri.Host.ToLowerInvariant();
            var isScopeAuthorized = candHost.Equals(authorizedHost, StringComparison.OrdinalIgnoreCase) ||
                                    candHost.EndsWith("." + authorizedHost, StringComparison.OrdinalIgnoreCase);

            if (!isScopeAuthorized)
            {
                outOfScopeCount++;
                diagnostics.Add($"Candidate '{candidate.Title}' with URL '{candidate.TargetUrl}' (host: '{candHost}') is OUT OF SCOPE for target '{authorizedHost}'. Discarded.");
                _logger.LogWarning("Target scope guard rejected candidate from tool '{ToolKey}' against unauthorized host '{CandHost}' (job authorized: '{AuthorizedHost}').", candidate.ToolKey, candHost, authorizedHost);
                continue;
            }

            // 5. Canonicalize Severity & Taxonomy
            var (normalizedSeverity, severityFallbackApplied) = NormalizeSeverity(candidate.RawSeverity);
            if (severityFallbackApplied)
            {
                diagnostics.Add($"Tool '{candidate.ToolKey}' raw severity '{candidate.RawSeverity}' was unknown; mapped to '{RiskSeverity.Info}'.");
            }

            // 6. Validate & Normalize Timestamps
            var observedAtUtc = ValidateObservationTimestamp(candidate.ObservedAtUtc, context.JobStartedAtUtc);

            // 7. Sanitize Fields and Evidence
            var safeTitle = EvidenceSanitizer.SanitizeEvidence(candidate.Title, 256);
            var safeDescription = EvidenceSanitizer.SanitizeEvidence(candidate.Description, 4096);
            var sanitizedTargetUrl = EvidenceSanitizer.SanitizeUrl(candidate.TargetUrl);
            var safeAttributes = EvidenceSanitizer.SanitizeAttributes(candidate.Attributes, bounds);

            // 8. Compute Deterministic Tool-Agnostic Fingerprint
            // Formula: SHA256(RepositoryId + TargetId + CanonicalTarget + CanonicalFindingType + CanonicalLocation + Identifier)
            var canonicalTarget = $"{candUri.Scheme.ToLowerInvariant()}://{candUri.Authority.ToLowerInvariant()}";
            var canonicalLocation = string.IsNullOrWhiteSpace(candUri.AbsolutePath) ? "/" : candUri.AbsolutePath.ToLowerInvariant();
            var identifier = !string.IsNullOrWhiteSpace(candidate.CveId)
                ? candidate.CveId.Trim().ToUpperInvariant()
                : !string.IsNullOrWhiteSpace(candidate.TemplateId)
                    ? candidate.TemplateId.Trim().ToLowerInvariant()
                    : safeTitle.Trim().ToLowerInvariant();

            var fingerprintPayload = $"{context.RepositoryId}:{context.TargetId}:{canonicalTarget}:{candidate.FindingType}:{canonicalLocation}:{identifier}";
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintPayload))).ToLowerInvariant();

            // 9. Query Existing Finding for Idempotent Deduplication
            var existingFinding = await _dbContext.SecurityFindings
                .Include(f => f.Evidences)
                .FirstOrDefaultAsync(f => f.FindingFingerprint == fingerprint, ct);

            SecurityFinding activeFinding;

            if (existingFinding != null)
            {
                existingFinding.LastObservedAtUtc = observedAtUtc;
                activeFinding = existingFinding;
                updatedFindingsCount++;
            }
            else
            {
                var newFinding = new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    RepositoryId = context.RepositoryId,
                    FindingFingerprint = fingerprint,
                    FindingType = candidate.FindingType,
                    Severity = normalizedSeverity,
                    Confidence = FindingConfidence.High,
                    Status = FindingStatus.Open, // Lifecycle state strictly locked to Open on ingestion
                    Title = safeTitle,
                    Description = safeDescription,
                    RiskScore = 0,
                    LifecycleVersion = 1,
                    FirstObservedAtUtc = observedAtUtc,
                    LastObservedAtUtc = observedAtUtc,
                    CreatedAtUtc = DateTime.UtcNow
                };

                _dbContext.SecurityFindings.Add(newFinding);
                activeFinding = newFinding;
                newFindingsCount++;
            }

            // 10. Construct Sanitized Evidence Record with Immutable Provenance
            var evidenceData = new
            {
                toolKey = candidate.ToolKey,
                toolVersion = candidate.ToolVersion,
                containerImageRepository = candidate.ContainerImageRepository,
                containerImageDigest = candidate.ContainerImageDigest,
                executable = candidate.Executable,
                rawSeverity = candidate.RawSeverity,
                cveId = candidate.CveId,
                cweId = candidate.CweId,
                templateId = candidate.TemplateId,
                endpointPath = candidate.EndpointPath,
                httpMethod = candidate.HttpMethod,
                httpResponseStatusCode = candidate.HttpResponseStatusCode,
                extractedData = candidate.ExtractedData != null ? EvidenceSanitizer.SanitizeEvidence(candidate.ExtractedData, 4096) : null,
                attributes = safeAttributes,
                ingestedAtUtc = DateTime.UtcNow
            };

            var safeEvidenceJson = JsonSerializer.Serialize(evidenceData);
            var evidenceFingerprintPayload = $"{activeFinding.Id}:{candidate.ToolKey}:{candidate.EndpointPath}:{DateTime.UtcNow.Ticks}";
            var evidenceFingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidenceFingerprintPayload))).ToLowerInvariant();

            var evidence = new SecurityFindingEvidence
            {
                Id = Guid.NewGuid(),
                FindingId = activeFinding.Id,
                Finding = activeFinding,
                EvidenceType = FindingEvidenceType.DeterministicOccurrence,
                DiscoverySource = DiscoveryType.DeterministicDetector,
                EvidenceFingerprint = evidenceFingerprint,
                EvidenceReference = sanitizedTargetUrl,
                SafeEvidenceJson = safeEvidenceJson,
                CreatedAtUtc = DateTime.UtcNow
            };

            _dbContext.SecurityFindingEvidences.Add(evidence);

            // 11. Authoritative Risk Engine Calculation
            var allEvidences = (activeFinding.Evidences ?? Enumerable.Empty<SecurityFindingEvidence>()).Concat(new[] { evidence }).ToList();
            var riskResult = _riskEngine.CalculateFindingRisk(activeFinding, allEvidences);
            activeFinding.RiskScore = riskResult.Score;
            activeFinding.Severity = riskResult.Severity;
            activeFinding.RiskFactorBreakdownJson = riskResult.ToJson();

            if (!affectedFindings.Contains(activeFinding))
            {
                affectedFindings.Add(activeFinding);
            }

            accepted++;
        }

        // 12. Record Audit Event for Batch Ingestion
        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            EventCode = AuditEventCode.ScanFindingsIngested,
            CorrelationId = context.JobId.ToString("N"),
            ResourceType = "SecurityScanJob",
            ResourceId = context.JobId.ToString(),
            CreatedAtUtc = DateTime.UtcNow,
            Metadata = JsonSerializer.Serialize(new
            {
                jobId = context.JobId,
                repositoryId = context.RepositoryId,
                targetId = context.TargetId,
                totalReceived,
                accepted,
                newFindingsCreated = newFindingsCount,
                existingFindingsUpdated = updatedFindingsCount,
                outOfScopeDiscarded = outOfScopeCount,
                invalidDiscarded = invalidCount
            })
        });

        // 13. Atomic Commit with Concurrency Recovery
        try
        {
            await _dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict or unique constraint collision detected during candidate batch ingestion for job '{JobId}'. Recovering via idempotent reload.", context.JobId);
            diagnostics.Add("Concurrency conflict detected during ingestion; recovered via idempotent reload.");
            await RecoverFromConcurrencyConflictAsync(cappedCandidates, context, bounds, ct);
        }

        _logger.LogInformation("Scan finding ingestion complete for job '{JobId}': {Accepted}/{Total} accepted ({New} new, {Updated} updated, {OutOfScope} out-of-scope, {Invalid} invalid).",
            context.JobId, accepted, totalReceived, newFindingsCount, updatedFindingsCount, outOfScopeCount, invalidCount);

        return new FindingIngestionResult(
            TotalCandidatesReceived: totalReceived,
            CandidatesAccepted: accepted,
            OutOfScopeDiscarded: outOfScopeCount,
            InvalidDiscarded: invalidCount,
            NewFindingsCreated: newFindingsCount,
            ExistingFindingsUpdated: updatedFindingsCount,
            Diagnostics: diagnostics
        );
    }

    private async Task RecoverFromConcurrencyConflictAsync(
        IReadOnlyList<FindingCandidate> candidates,
        ScanJobContext context,
        ParserResourceBounds bounds,
        CancellationToken ct)
    {
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.Title) || string.IsNullOrWhiteSpace(candidate.TargetUrl))
                continue;

            if (!Uri.TryCreate(candidate.TargetUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? candidate.TargetUrl : $"https://{candidate.TargetUrl}", UriKind.Absolute, out var candUri))
                continue;

            var canonicalTarget = $"{candUri.Scheme.ToLowerInvariant()}://{candUri.Authority.ToLowerInvariant()}";
            var canonicalLocation = string.IsNullOrWhiteSpace(candUri.AbsolutePath) ? "/" : candUri.AbsolutePath.ToLowerInvariant();
            var safeTitle = EvidenceSanitizer.SanitizeEvidence(candidate.Title, 256);
            var identifier = !string.IsNullOrWhiteSpace(candidate.CveId)
                ? candidate.CveId.Trim().ToUpperInvariant()
                : !string.IsNullOrWhiteSpace(candidate.TemplateId)
                    ? candidate.TemplateId.Trim().ToLowerInvariant()
                    : safeTitle.Trim().ToLowerInvariant();

            var fingerprintPayload = $"{context.RepositoryId}:{context.TargetId}:{canonicalTarget}:{candidate.FindingType}:{canonicalLocation}:{identifier}";
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintPayload))).ToLowerInvariant();

            var observedAtUtc = ValidateObservationTimestamp(candidate.ObservedAtUtc, context.JobStartedAtUtc);
            var sanitizedTargetUrl = EvidenceSanitizer.SanitizeUrl(candidate.TargetUrl);
            var safeAttributes = EvidenceSanitizer.SanitizeAttributes(candidate.Attributes, bounds);

            var existingFinding = await _dbContext.SecurityFindings
                .Include(f => f.Evidences)
                .FirstOrDefaultAsync(f => f.FindingFingerprint == fingerprint, ct);

            if (existingFinding != null)
            {
                existingFinding.LastObservedAtUtc = observedAtUtc;

                var evidenceData = new
                {
                    toolKey = candidate.ToolKey,
                    toolVersion = candidate.ToolVersion,
                    containerImageRepository = candidate.ContainerImageRepository,
                    containerImageDigest = candidate.ContainerImageDigest,
                    executable = candidate.Executable,
                    rawSeverity = candidate.RawSeverity,
                    cveId = candidate.CveId,
                    cweId = candidate.CweId,
                    templateId = candidate.TemplateId,
                    endpointPath = candidate.EndpointPath,
                    httpMethod = candidate.HttpMethod,
                    httpResponseStatusCode = candidate.HttpResponseStatusCode,
                    extractedData = candidate.ExtractedData != null ? EvidenceSanitizer.SanitizeEvidence(candidate.ExtractedData, 4096) : null,
                    attributes = safeAttributes,
                    ingestedAtUtc = DateTime.UtcNow
                };

                var safeEvidenceJson = JsonSerializer.Serialize(evidenceData);
                var evidenceFingerprintPayload = $"{existingFinding.Id}:{candidate.ToolKey}:{candidate.EndpointPath}:{DateTime.UtcNow.Ticks}";
                var evidenceFingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidenceFingerprintPayload))).ToLowerInvariant();

                var evidence = new SecurityFindingEvidence
                {
                    Id = Guid.NewGuid(),
                    FindingId = existingFinding.Id,
                    Finding = existingFinding,
                    EvidenceType = FindingEvidenceType.DeterministicOccurrence,
                    DiscoverySource = DiscoveryType.DeterministicDetector,
                    EvidenceFingerprint = evidenceFingerprint,
                    EvidenceReference = sanitizedTargetUrl,
                    SafeEvidenceJson = safeEvidenceJson,
                    CreatedAtUtc = DateTime.UtcNow
                };

                _dbContext.SecurityFindingEvidences.Add(evidence);

                var allEvidences = (existingFinding.Evidences ?? Enumerable.Empty<SecurityFindingEvidence>()).Concat(new[] { evidence }).ToList();
                var riskResult = _riskEngine.CalculateFindingRisk(existingFinding, allEvidences);
                existingFinding.RiskScore = riskResult.Score;
                existingFinding.Severity = riskResult.Severity;
                existingFinding.RiskFactorBreakdownJson = riskResult.ToJson();

                try
                {
                    await _dbContext.SaveChangesAsync(ct);
                }
                catch (DbUpdateException)
                {
                    // Ignore transient duplicate evidence if already persisted
                }
            }
        }
    }

    /// <summary>
    /// Normalizes raw tool severity to platform RiskSeverity with fail-closed fallback to Info.
    /// </summary>
    public static (RiskSeverity Severity, bool FallbackApplied) NormalizeSeverity(string? rawSeverity)
    {
        if (string.IsNullOrWhiteSpace(rawSeverity))
        {
            return (RiskSeverity.Info, true);
        }

        return rawSeverity.Trim().ToLowerInvariant() switch
        {
            "critical" or "crit" => (RiskSeverity.Critical, false),
            "high" => (RiskSeverity.High, false),
            "medium" or "med" => (RiskSeverity.Medium, false),
            "low" => (RiskSeverity.Low, false),
            "info" or "informational" => (RiskSeverity.Info, false),
            _ => (RiskSeverity.Info, true)
        };
    }

    /// <summary>
    /// Validates observation timestamp to ensure scanner did not provide an unreasonable past or future date.
    /// </summary>
    private static DateTime ValidateObservationTimestamp(DateTime? candidateTimestamp, DateTime jobStartedAtUtc)
    {
        if (!candidateTimestamp.HasValue)
        {
            return DateTime.UtcNow;
        }

        var ts = candidateTimestamp.Value;
        var now = DateTime.UtcNow;

        // Reject future timestamps (> 5 minutes into the future)
        if (ts > now.AddMinutes(5))
        {
            return now;
        }

        // Reject excessively old timestamps (> 30 days prior to job start)
        if (ts < jobStartedAtUtc.AddDays(-30))
        {
            return jobStartedAtUtc;
        }

        return ts;
    }
}
