using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
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
    ILogger<SecretDetectionService> logger,
    IObjectStore? objectStore = null,
    IRepositoryProvider? repositoryProvider = null)
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

        // Self-healing: If all files were marked analyzed but 0 candidates were found (e.g. earlier ephemeral disk wipe), re-evaluate!
        if (filesToAnalyze.Count == 0 && snapshot.CandidatesFound == 0)
        {
            filesToAnalyze = await dbContext.SnapshotFiles
                .Where(sf => sf.SnapshotId == snapshotId)
                .ToListAsync(ct);
        }

        int totalCandidatesFound = 0;
        var opts = options.Value;

        // 1. Check for reusable content hashes from previous snapshots of this repository
        var contentHashes = filesToAnalyze.Select(f => f.ContentHash).Distinct().ToList();
        var reusableOccurrencesMap = await snapshotService.GetReusableOccurrencesForHashesAsync(snapshot.RepositoryId, contentHashes, ct);

        // 2. Load pending file contents from tarball archive in ObjectStore (or re-stream from GitHub if ephemeral disk was cleared)
        var fileContents = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Stream? archiveStream = null;

        if (objectStore != null && !string.IsNullOrWhiteSpace(snapshot.ArchiveObjectKey))
        {
            try
            {
                if (await objectStore.ExistsAsync(snapshot.ArchiveObjectKey, ct))
                {
                    archiveStream = await objectStore.GetAsync(snapshot.ArchiveObjectKey, ct);
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed reading existing object store archive {Key}", snapshot.ArchiveObjectKey);
            }
        }

        // Ephemeral container self-healing: automatically stream from GitHub if file was lost on Render container restart
        if (archiveStream == null && repositoryProvider != null && snapshot.Repository != null && !string.IsNullOrWhiteSpace(snapshot.CommitSha))
        {
            try
            {
                logger.LogInformation("Repository archive missing from ObjectStore for snapshot {SnapshotId}. Streaming from GitHub for {Owner}/{Name} @ {Commit}...",
                    snapshotId, snapshot.Repository.Owner, snapshot.Repository.Name, snapshot.CommitSha);

                var downloaded = await repositoryProvider.DownloadArchiveAsync(
                    snapshot.Repository.Owner,
                    snapshot.Repository.Name,
                    snapshot.CommitSha,
                    ct);

                if (objectStore != null && !string.IsNullOrWhiteSpace(snapshot.ArchiveObjectKey))
                {
                    await objectStore.PutAsync(snapshot.ArchiveObjectKey, downloaded, "application/gzip", ct);
                    archiveStream = await objectStore.GetAsync(snapshot.ArchiveObjectKey, ct);
                }
                else
                {
                    archiveStream = downloaded;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed streaming archive from GitHub for snapshot {SnapshotId}", snapshotId);
            }
        }

        if (archiveStream != null)
        {
            try
            {
                var newlyCatalogedFiles = new List<SnapshotFile>();
                var pendingPaths = filesToAnalyze
                    .Where(f => !f.IsSkipped && !reusableOccurrencesMap.ContainsKey(f.ContentHash))
                    .Select(f => NormalizePath(f.FilePath))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                await using (archiveStream)
                await using (var gzipStream = new GZipStream(archiveStream, CompressionMode.Decompress))
                using (var tarReader = new TarReader(gzipStream))
                {
                    TarEntry? entry;
                    while ((entry = await tarReader.GetNextEntryAsync(false, ct)) != null)
                    {
                        if (entry.EntryType == TarEntryType.Directory || entry.EntryType == TarEntryType.SymbolicLink || entry.EntryType == TarEntryType.HardLink)
                        {
                            continue;
                        }

                        var rawName = entry.Name;
                        if (rawName.Contains("..")) continue;

                        var slashIdx = rawName.IndexOf('/');
                        var relPath = NormalizePath(slashIdx >= 0 ? rawName[(slashIdx + 1)..] : rawName);
                        if (string.IsNullOrWhiteSpace(relPath)) continue;

                        if (filesToAnalyze.Count == 0)
                        {
                            // Self-catalog snapshot files directly from archive if database records were missing
                            var fileName = Path.GetFileName(relPath);
                            var extension = Path.GetExtension(relPath).ToLowerInvariant();
                            var sizeBytes = entry.Length;

                            byte[] bytes = Array.Empty<byte>();
                            if (entry.DataStream != null && sizeBytes <= (opts.MaxFileSizeMb * 1024 * 1024))
                            {
                                using var ms = new MemoryStream();
                                await entry.DataStream.CopyToAsync(ms, ct);
                                bytes = ms.ToArray();
                            }

                            using var sha256 = System.Security.Cryptography.SHA256.Create();
                            var hashBytes = sha256.ComputeHash(bytes);
                            var contentHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

                            bool isBinary = IsBinaryExtension(extension);
                            bool isTooLarge = sizeBytes > (opts.MaxFileSizeMb * 1024 * 1024);
                            bool isVendored = IsVendoredPath(relPath);

                            SkipReason? skipReason = null;
                            if (isBinary) skipReason = SkipReason.Binary;
                            else if (isTooLarge) skipReason = SkipReason.TooLarge;
                            else if (isVendored) skipReason = SkipReason.VendoredLib;

                            var sf = new SnapshotFile
                            {
                                SnapshotId = snapshotId,
                                FilePath = relPath,
                                FileName = fileName,
                                FileExtension = string.IsNullOrEmpty(extension) ? null : extension,
                                ContentHash = contentHash,
                                SizeBytes = sizeBytes,
                                IsAnalyzed = false,
                                IsBinary = isBinary,
                                IsSkipped = skipReason.HasValue,
                                SkipReason = skipReason
                            };
                            newlyCatalogedFiles.Add(sf);

                            if (!sf.IsSkipped && !isBinary && bytes.Length > 0)
                            {
                                fileContents[relPath] = Encoding.UTF8.GetString(bytes);
                            }
                        }
                        else if (pendingPaths.Contains(relPath) && entry.DataStream != null && entry.Length < (opts.MaxFileSizeMb * 1024 * 1024))
                        {
                            using var ms = new MemoryStream();
                            await entry.DataStream.CopyToAsync(ms, ct);
                            fileContents[relPath] = Encoding.UTF8.GetString(ms.ToArray());
                        }
                    }
                }

                if (newlyCatalogedFiles.Count > 0)
                {
                    logger.LogInformation("Self-cataloged {FileCount} snapshot files from archive for snapshot {SnapshotId}", newlyCatalogedFiles.Count, snapshotId);
                    dbContext.SnapshotFiles.AddRange(newlyCatalogedFiles);
                    snapshot.FileCount = newlyCatalogedFiles.Count;
                    snapshot.TotalSizeBytes = newlyCatalogedFiles.Sum(f => f.SizeBytes);
                    await dbContext.SaveChangesAsync(ct);
                    filesToAnalyze = newlyCatalogedFiles;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed reading tarball archive for snapshot {SnapshotId}", snapshotId);
            }
        }
        else
        {
            logger.LogWarning("No archive stream available for snapshot {SnapshotId}. Files could not be extracted.", snapshotId);
        }

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
                        SnapshotFileId = file.Id,
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

            // 2. Perform actual regex secret detection if file content is available
            try
            {
                var normPath = NormalizePath(file.FilePath);
                if (fileContents.TryGetValue(normPath, out var content) && !string.IsNullOrWhiteSpace(content))
                {
                    var occurrences = await ProcessFileContentScanAsync(file, content, snapshot.RepositoryId, ct);
                    totalCandidatesFound += occurrences.Count;
                    file.IsAnalyzed = true;
                }
                else if (fileContents.Count > 0 || archiveStream != null)
                {
                    // Archive was present and read, file was simply empty or had no secrets
                    file.IsAnalyzed = true;
                }
                onFileProcessed?.Invoke(file.Id);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed analyzing file {FilePath} in snapshot {SnapshotId}", file.FilePath, snapshotId);
            }
        }

        if (archiveStream != null || fileContents.Count > 0 || reusableOccurrencesMap.Count > 0)
        {
            snapshot.CandidatesFound = totalCandidatesFound;
            snapshot.AnalysisStatus = AnalysisStatus.Completed;
            snapshot.AnalysisCompletedAtUtc = DateTime.UtcNow;
            logger.LogInformation("Snapshot {SnapshotId} analysis completed. Analyzed {FileCount} files, found {CandidatesFound} candidates.",
                snapshotId, filesToAnalyze.Count, totalCandidatesFound);
        }
        else
        {
            logger.LogWarning("No archive stream available for snapshot {SnapshotId}. Marking Failed for retry.", snapshotId);
            snapshot.AnalysisStatus = AnalysisStatus.Failed;
        }

        await dbContext.SaveChangesAsync(ct);
        return totalCandidatesFound;
    }

    public async Task<List<CandidateOccurrence>> ProcessFileContentScanAsync(
        SnapshotFile snapshotFile,
        string fileContent,
        Guid? repositoryId = null,
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

                // Auto-enqueue validation job so CredentialValidationWorker immediately tests connection
                dbContext.AnalysisJobs.Add(new AnalysisJob
                {
                    JobType = JobType.CredentialValidation,
                    Status = JobStatus.Queued,
                    TargetEntityType = "Candidate",
                    TargetEntityId = candidate.Id,
                    PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        candidateId = candidate.Id,
                        providerName = candidate.CredentialType
                    }),
                    QueuedAtUtc = DateTime.UtcNow
                });
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
                    RepositoryId = repositoryId ?? snapshotFile.Snapshot?.RepositoryId ?? Guid.Empty,
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

    private static string NormalizePath(string p) => p.Replace('\\', '/').TrimStart('.', '/').Trim();

    private static bool IsBinaryExtension(string ext) =>
        ext is ".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp" or ".ico" or ".pdf" or ".zip" or ".tar" or ".gz" or ".exe" or ".dll" or ".so" or ".dylib" or ".bin" or ".woff" or ".woff2" or ".ttf" or ".eot";

    private static bool IsVendoredPath(string path) =>
        path.StartsWith("node_modules/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("vendor/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(".git/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("dist/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("build/", StringComparison.OrdinalIgnoreCase);
}
