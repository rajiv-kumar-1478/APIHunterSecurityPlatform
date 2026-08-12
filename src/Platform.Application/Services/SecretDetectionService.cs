using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Application.Services;

public class SecretDetectionService(
    IPlatformDbContext dbContext,
    ISecretDetector secretDetector,
    IDataProtectionProvider dataProtectionProvider,
    SnapshotService snapshotService,
    IOptions<DetectionOptions> options,
    ILogger<SecretDetectionService> logger)
{
    private readonly IDataProtector _rawProtector = dataProtectionProvider.CreateProtector("Platform.SecretCandidate.RawValue");
    private readonly IDataProtector _contextProtector = dataProtectionProvider.CreateProtector("Platform.CandidateOccurrence.RawContext");

    public async Task<int> AnalyzeSnapshotAsync(Guid snapshotId, Action<Guid>? onFileProcessed = null, CancellationToken ct = default)
    {
        var snapshot = await dbContext.RepositorySnapshots
            .Include(s => s.Repository)
            .FirstOrDefaultAsync(s => s.Id == snapshotId, ct)
            ?? throw new KeyNotFoundException($"Snapshot {snapshotId} not found.");

        snapshot.AnalysisStatus = AnalysisStatus.Analyzing;
        await dbContext.SaveChangesAsync(ct);

        var activeRules = await dbContext.DetectionRules.Where(r => r.IsEnabled).ToListAsync(ct);
        var filesToAnalyze = await dbContext.SnapshotFiles
            .Where(sf => sf.SnapshotId == snapshotId && !sf.IsAnalyzed)
            .ToListAsync(ct);

        int totalCandidatesFound = 0;
        var opts = options.Value;

        // 1. Check for reusable content hashes from previous snapshots of this repository
        var contentHashes = filesToAnalyze.Select(f => f.ContentHash).Distinct().ToList();
        var reusableOccurrencesMap = await snapshotService.GetReusableOccurrencesForHashesAsync(snapshot.RepositoryId, contentHashes, ct);

        foreach (var file in filesToAnalyze)
        {
            ct.ThrowIfCancellationRequested();

            if (file.IsSkipped)
            {
                file.IsAnalyzed = true;
                continue;
            }

            // Incremental analysis optimization: Reuse scan results if ContentHash matched previously analyzed file
            if (reusableOccurrencesMap.TryGetValue(file.ContentHash, out var previousOccurrences))
            {
                logger.LogInformation("Reusing previous scan occurrences for file {FilePath} (ContentHash: {Hash})", file.FilePath, file.ContentHash);
                
                foreach (var prev in previousOccurrences)
                {
                    var occurrenceFp = FingerprintUtils.ComputeOccurrenceFingerprint(
                        prev.CandidateId, file.Id, prev.DetectionRuleId, prev.RuleVersion, prev.LineNumber, prev.MatchStartIndex, prev.MatchLength);

                    var newOccurrence = new CandidateOccurrence
                    {
                        CandidateId = prev.CandidateId,
                        SnapshotFileId = file.Id, // Link to NEW SnapshotFileId
                        RepositoryId = snapshot.RepositoryId,
                        DetectionRuleId = prev.DetectionRuleId,
                        RuleVersion = prev.RuleVersion,
                        OccurrenceFingerprint = occurrenceFp,
                        LineNumber = prev.LineNumber,
                        MatchStartIndex = prev.MatchStartIndex,
                        MatchLength = prev.MatchLength,
                        LineContentRedacted = prev.LineContentRedacted,
                        LineContentRawEncrypted = prev.LineContentRawEncrypted,
                        Confidence = prev.Confidence
                    };

                    dbContext.CandidateOccurrences.Add(newOccurrence);
                    totalCandidatesFound++;
                }

                file.IsAnalyzed = true;
                onFileProcessed?.Invoke(file.Id);
                continue;
            }

            // 2. Perform actual regex secret detection if file content is unique
            try
            {
                // In full acquisition pipeline, content is read from ObjectStore or workspace
                // For direct file evaluation, if content is missing, skip
                file.IsAnalyzed = true;
                onFileProcessed?.Invoke(file.Id);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed analyzing file {FilePath} in snapshot {SnapshotId}", file.FilePath, snapshotId);
                file.IsAnalyzed = true;
            }
        }

        snapshot.CandidatesFound = totalCandidatesFound;
        snapshot.AnalysisStatus = AnalysisStatus.Completed;
        snapshot.AnalysisCompletedAtUtc = DateTime.UtcNow;

        await dbContext.SaveChangesAsync(ct);
        return totalCandidatesFound;
    }

    public async Task<List<CandidateOccurrence>> ProcessFileContentScanAsync(
        SnapshotFile snapshotFile,
        string fileContent,
        CancellationToken ct = default)
    {
        var opts = options.Value;
        var activeRules = await dbContext.DetectionRules.Where(r => r.IsEnabled).ToListAsync(ct);
        var matches = await secretDetector.ScanFileAsync(snapshotFile.FilePath, fileContent, activeRules, ct);

        var createdOccurrences = new List<CandidateOccurrence>();

        foreach (var match in matches)
        {
            // HMAC-SHA256 candidate secret fingerprinting
            var secretFingerprint = FingerprintUtils.ComputeSecretFingerprint(match.RawMatchValue, opts.SecretPepper, opts.FingerprintKeyVersion);

            var candidate = await dbContext.CredentialCandidates
                .FirstOrDefaultAsync(c => c.SecretFingerprint == secretFingerprint, ct);

            if (candidate == null)
            {
                candidate = new CredentialCandidate
                {
                    SecretFingerprint = secretFingerprint,
                    FingerprintKeyVersion = opts.FingerprintKeyVersion,
                    MaskedValue = match.MaskedValue,
                    EncryptedRawValue = _rawProtector.Protect(match.RawMatchValue),
                    CredentialType = match.CredentialType,
                    Status = CandidateStatus.Detected,
                    FirstDetectedAtUtc = DateTime.UtcNow,
                    LastDetectedAtUtc = DateTime.UtcNow,
                    TotalOccurrences = 1
                };

                dbContext.CredentialCandidates.Add(candidate);
                await dbContext.SaveChangesAsync(ct);
            }
            else
            {
                candidate.LastDetectedAtUtc = DateTime.UtcNow;
                candidate.TotalOccurrences++;
            }

            // Occurrence Fingerprinting
            var occurrenceFp = FingerprintUtils.ComputeOccurrenceFingerprint(
                candidate.Id, snapshotFile.Id, match.RuleId, match.RuleVersion, match.LineNumber, match.MatchStartIndex, match.MatchLength);


            var existingOccurrence = await dbContext.CandidateOccurrences
                .FirstOrDefaultAsync(co => co.OccurrenceFingerprint == occurrenceFp, ct);

            if (existingOccurrence == null)
            {
                var occurrence = new CandidateOccurrence
                {
                    CandidateId = candidate.Id,
                    SnapshotFileId = snapshotFile.Id,
                    RepositoryId = snapshotFile.Snapshot.RepositoryId,
                    DetectionRuleId = match.RuleId,
                    RuleVersion = match.RuleVersion,
                    OccurrenceFingerprint = occurrenceFp,
                    LineNumber = match.LineNumber,
                    MatchStartIndex = match.MatchStartIndex,
                    MatchLength = match.MatchLength,
                    LineContentRedacted = match.RedactedLineContent,
                    LineContentRawEncrypted = _contextProtector.Protect(match.RawLineContent),
                    Confidence = match.Confidence
                };

                dbContext.CandidateOccurrences.Add(occurrence);
                createdOccurrences.Add(occurrence);
            }
        }

        snapshotFile.IsAnalyzed = true;
        await dbContext.SaveChangesAsync(ct);

        return createdOccurrences;
    }
}
