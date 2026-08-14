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
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Application.Scanning;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative ingestion engine processing untrusted scanner outputs into trusted Phase 6 SecurityFinding records.
/// Enforces canonical target scope authorization, deterministic deduplication fingerprints, evidence sanitization,
/// timestamp bounds, and lifecycle state initialization.
/// </summary>
public class ScanFindingIngestionEngine
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<ScanFindingIngestionEngine> _logger;

    public ScanFindingIngestionEngine(
        IPlatformDbContext dbContext,
        ILogger<ScanFindingIngestionEngine> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
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

        // 1. Resolve Authorized Job Target Host
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

        foreach (var candidate in cappedCandidates)
        {
            // 3. Validate Candidate Structure
            if (string.IsNullOrWhiteSpace(candidate.Title) || string.IsNullOrWhiteSpace(candidate.TargetUrl))
            {
                invalidCount++;
                diagnostics.Add($"Candidate from tool '{candidate.ToolKey}' discarded: missing Title or TargetUrl.");
                continue;
            }

            // 4. Strict Canonical Scope Validation
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
                .FirstOrDefaultAsync(f => f.FindingFingerprint == fingerprint, ct);

            Guid findingId;

            if (existingFinding != null)
            {
                existingFinding.LastObservedAtUtc = observedAtUtc;
                findingId = existingFinding.Id;
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
                    RiskScore = 0, // Authoritative Risk Engine calculates risk score
                    LifecycleVersion = 1,
                    FirstObservedAtUtc = observedAtUtc,
                    LastObservedAtUtc = observedAtUtc,
                    CreatedAtUtc = DateTime.UtcNow
                };

                _dbContext.SecurityFindings.Add(newFinding);
                findingId = newFinding.Id;
                newFindingsCount++;
            }

            // 10. Construct Sanitized Evidence Record
            var evidenceData = new
            {
                toolKey = candidate.ToolKey,
                toolVersion = candidate.ToolVersion,
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
            var evidenceFingerprintPayload = $"{findingId}:{candidate.ToolKey}:{candidate.EndpointPath}:{DateTime.UtcNow.Ticks}";
            var evidenceFingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidenceFingerprintPayload))).ToLowerInvariant();

            var evidence = new SecurityFindingEvidence
            {
                Id = Guid.NewGuid(),
                FindingId = findingId,
                EvidenceType = FindingEvidenceType.DeterministicOccurrence,
                DiscoverySource = DiscoveryType.DeterministicDetector,
                EvidenceFingerprint = evidenceFingerprint,
                EvidenceReference = sanitizedTargetUrl,
                SafeEvidenceJson = safeEvidenceJson,
                CreatedAtUtc = DateTime.UtcNow
            };

            _dbContext.SecurityFindingEvidences.Add(evidence);
            accepted++;
        }

        if (newFindingsCount > 0 || updatedFindingsCount > 0)
        {
            await _dbContext.SaveChangesAsync(ct);
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
