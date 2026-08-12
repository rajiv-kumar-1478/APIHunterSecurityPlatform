using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Analyzes persisted repository snapshot history to detect credential exposures that persist
/// across multiple distinct commit snapshots (>= 2 distinct CommitShas).
/// 
/// Key invariants:
/// - Strictly an analysis layer: reads existing persisted RepositorySnapshot, SnapshotFile, CandidateOccurrence.
/// - Canonical finding identity: CoreEntityId = CandidateId.ToString("N").
/// - Occurrence-granular evidence: SourceEntityId includes SnapshotId, SnapshotFileId, and LineNumber.
/// - Zero direct RiskEngine dependency: all risk calculation flows through SecurityFindingService.
/// - CandidateStatus remains untouched.
/// - SafeEvidenceJson uses allowlist-only projection (commitSha, acquiredAtUtc, filePath, lineNumber, maskedValue).
/// </summary>
public class ExposureAnalysisService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly ILogger<ExposureAnalysisService> _logger;

    public ExposureAnalysisService(
        IPlatformDbContext dbContext,
        SecurityFindingService findingService,
        ILogger<ExposureAnalysisService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _findingService = findingService ?? throw new ArgumentNullException(nameof(findingService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Analyzes candidate occurrences across distinct commit snapshots for the target repository.
    /// Idempotent — safe to re-run repeatedly.
    /// </summary>
    public async Task AnalyzeRepositorySnapshotHistoryAsync(Guid repositoryId, CancellationToken ct = default)
    {
        _logger.LogInformation("Starting multi-snapshot exposure analysis for repository '{RepositoryId}'.", repositoryId);

        var occurrences = await _dbContext.CandidateOccurrences
            .Include(o => o.Candidate)
            .Include(o => o.SnapshotFile)
                .ThenInclude(f => f.Snapshot)
            .Where(o => o.RepositoryId == repositoryId)
            .ToListAsync(ct);

        if (occurrences.Count == 0)
        {
            _logger.LogInformation("No occurrences found for repository '{RepositoryId}'. Multi-snapshot analysis completed.", repositoryId);
            return;
        }

        var occurrencesByCandidate = occurrences.GroupBy(o => o.CandidateId);

        foreach (var candidateGroup in occurrencesByCandidate)
        {
            var candidate = candidateGroup.First().Candidate;
            if (candidate == null) continue;

            // Collect distinct snapshots (by CommitSha)
            var distinctSnapshots = candidateGroup
                .Select(o => o.SnapshotFile.Snapshot)
                .Where(s => s != null)
                .GroupBy(s => s.CommitSha)
                .Select(g => g.First())
                .OrderBy(s => s.AcquiredAtUtc)
                .ToList();

            string coreEntityId = candidate.Id.ToString("N");
            SecurityFinding? historicalFinding = null;

            // 1. If exposed across >= 2 distinct commit snapshots, upsert HistoricalExposureDetected finding
            if (distinctSnapshots.Count >= 2)
            {
                var firstSnapshot = distinctSnapshots.First();
                var latestSnapshot = distinctSnapshots.Last();

                string firstShaShort = ShortenSha(firstSnapshot.CommitSha);
                string latestShaShort = ShortenSha(latestSnapshot.CommitSha);

                historicalFinding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                    RepositoryId: repositoryId,
                    SnapshotId: latestSnapshot.Id,
                    FindingType: FindingType.HistoricalExposureDetected,
                    Severity: RiskSeverity.Medium,
                    Confidence: FindingConfidence.High,
                    Title: "Historical credential exposure detected across multiple commit snapshots",
                    Description: $"Credential '{candidate.MaskedValue}' was detected across {distinctSnapshots.Count} distinct commit snapshots ({firstShaShort} to {latestShaShort}).",
                    CoreEntityId: coreEntityId
                ), ct);
            }

            // 2. Lookup existing Validated or Unvalidated credential findings for this candidate
            string validatedFindingCoreId = candidate.Id.ToString("N");
            var existingValidatedFinding = await _dbContext.SecurityFindings
                .FirstOrDefaultAsync(f => f.RepositoryId == repositoryId &&
                                         f.FindingType == FindingType.ValidatedCredentialExposed &&
                                         f.FindingFingerprint == SecurityFindingService.ComputeFindingFingerprint(repositoryId, FindingType.ValidatedCredentialExposed, validatedFindingCoreId), ct);

            var existingUnvalidatedFinding = await _dbContext.SecurityFindings
                .FirstOrDefaultAsync(f => f.RepositoryId == repositoryId &&
                                         f.FindingType == FindingType.UnvalidatedCredentialExposed &&
                                         f.FindingFingerprint == SecurityFindingService.ComputeFindingFingerprint(repositoryId, FindingType.UnvalidatedCredentialExposed, validatedFindingCoreId), ct);

            // 3. Attach occurrence-granular HistoricalCommit evidence to all relevant findings
            foreach (var occ in candidateGroup)
            {
                var snapshot = occ.SnapshotFile.Snapshot;
                if (snapshot == null) continue;

                // Occurrence-granular SourceEntityId: includes SnapshotId, SnapshotFileId, LineNumber
                string sourceEntityId = $"historical:{candidate.Id:N}:{snapshot.Id:N}:{occ.SnapshotFileId:N}:{occ.LineNumber}";
                string shortSha = ShortenSha(snapshot.CommitSha);
                string evidenceRef = $"Commit {shortSha} ({occ.SnapshotFile.FilePath}:L{occ.LineNumber})";
                string safeJson = ProjectSafeEvidenceJson(snapshot, occ, candidate);

                var attachRequest = new AttachEvidenceRequest(
                    EvidenceType: FindingEvidenceType.HistoricalCommit,
                    DiscoverySource: DiscoveryType.DeterministicDetector,
                    SourceEntityId: sourceEntityId,
                    SnapshotId: snapshot.Id,
                    SnapshotFileId: occ.SnapshotFileId,
                    CandidateId: candidate.Id,
                    EvidenceReference: evidenceRef,
                    SafeEvidenceJson: safeJson
                );

                // Attach to HistoricalExposureDetected finding if created
                if (historicalFinding != null)
                {
                    await _findingService.AttachEvidenceAsync(historicalFinding.Id, attachRequest, ct);
                }

                // Attach to existing Validated finding if present
                if (existingValidatedFinding != null)
                {
                    await _findingService.AttachEvidenceAsync(existingValidatedFinding.Id, attachRequest, ct);
                }

                // Attach to existing Unvalidated finding if present
                if (existingUnvalidatedFinding != null)
                {
                    await _findingService.AttachEvidenceAsync(existingUnvalidatedFinding.Id, attachRequest, ct);
                }
            }
        }

        _logger.LogInformation("Completed multi-snapshot exposure analysis for repository '{RepositoryId}'.", repositoryId);
    }

    private static string ShortenSha(string sha)
    {
        if (string.IsNullOrWhiteSpace(sha)) return "unknown";
        return sha.Length > 7 ? sha[..7] : sha;
    }

    internal static string ProjectSafeEvidenceJson(RepositorySnapshot snapshot, CandidateOccurrence occ, CredentialCandidate candidate)
    {
        return JsonSerializer.Serialize(new
        {
            commitSha = ShortenSha(snapshot.CommitSha),
            fullCommitSha = snapshot.CommitSha,
            acquiredAtUtc = snapshot.AcquiredAtUtc,
            filePath = occ.SnapshotFile?.FilePath ?? string.Empty,
            lineNumber = occ.LineNumber,
            maskedValue = candidate.MaskedValue
        });
    }
}
