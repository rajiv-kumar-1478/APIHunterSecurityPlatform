using System.Formats.Tar;
using System.IO.Compression;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;


namespace Platform.Application.Services;

public class RepositoryAcquisitionService(
    IPlatformDbContext dbContext,
    IRepositoryProvider repositoryProvider,
    IObjectStore objectStore,
    JobOrchestrationService jobOrchestrationService,
    IAuditService auditService,
    IOptions<DetectionOptions> options,
    ILogger<RepositoryAcquisitionService> logger)
{
    public async Task<Repository> AddRepositoryAsync(string url, Guid? userId = null, CancellationToken ct = default)
    {
        var (owner, name) = ParseGitHubUrl(url);
        var meta = await repositoryProvider.GetRepositoryMetadataAsync(owner, name, ct);

        var repo = await dbContext.Repositories
            .FirstOrDefaultAsync(r => r.Provider == repositoryProvider.ProviderName && r.ProviderRepoId == meta.ProviderRepoId, ct);

        if (repo == null)
        {
            repo = new Repository
            {
                Provider = repositoryProvider.ProviderName,
                ProviderRepoId = meta.ProviderRepoId,
                Owner = meta.Owner,
                Name = meta.Name,
                FullName = meta.FullName,
                Url = meta.Url,
                Description = meta.Description,
                IsPrivate = meta.IsPrivate,
                DefaultBranch = meta.DefaultBranch,
                AcquisitionStatus = AcquisitionStatus.Pending
            };

            dbContext.Repositories.Add(repo);
            await dbContext.SaveChangesAsync(ct);
        }

        // Add source provenance
        var source = await dbContext.RepositorySources
            .FirstOrDefaultAsync(rs => rs.RepositoryId == repo.Id && rs.DiscoveryType == DiscoveryType.AdminManual, ct);

        if (source == null)
        {
            source = new RepositorySource
            {
                RepositoryId = repo.Id,
                DiscoveryType = DiscoveryType.AdminManual,
                DiscoveredViaQuery = "Admin Manual URL"
            };
            dbContext.RepositorySources.Add(source);
            await dbContext.SaveChangesAsync(ct);
        }

        await auditService.RecordAsync(
            AuditEventCode.RepositoryAdded,
            userId,
            null,
            "127.0.0.1",
            new { RepositoryId = repo.Id, FullName = repo.FullName, Url = repo.Url },
            ct);

        return repo;
    }

    public async Task<int> SeedRepositoriesFromApiHunterAsync(Guid? userId = null, CancellationToken ct = default)
    {
        logger.LogInformation("Starting repository seeding from APIHunter records and repo references...");

        var repoRefs = await dbContext.ApiHunterRepoReferences
            .Include(rr => rr.ApiHunterRecord)
            .Where(rr => rr.RepoOwner != null && rr.RepoName != null)
            .ToListAsync(ct);

        int count = 0;
        foreach (var refGroup in repoRefs.GroupBy(r => (r.RepoOwner!.ToLowerInvariant(), r.RepoName!.ToLowerInvariant())))
        {
            var sample = refGroup.First();
            var owner = sample.RepoOwner!;
            var name = sample.RepoName!;

            try
            {
                var repo = await dbContext.Repositories
                    .FirstOrDefaultAsync(r => r.Owner.ToLower() == owner && r.Name.ToLower() == name, ct);

                if (repo == null)
                {
                    RepositoryMetadata meta;
                    try
                    {
                        meta = await repositoryProvider.GetRepositoryMetadataAsync(owner, name, ct);
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Failed to fetch metadata for APIHunter repo {Owner}/{Name}", owner, name);
                        continue;
                    }

                    repo = new Repository
                    {
                        Provider = repositoryProvider.ProviderName,
                        ProviderRepoId = meta.ProviderRepoId,
                        Owner = meta.Owner,
                        Name = meta.Name,
                        FullName = meta.FullName,
                        Url = meta.Url,
                        Description = meta.Description,
                        IsPrivate = meta.IsPrivate,
                        DefaultBranch = meta.DefaultBranch,
                        AcquisitionStatus = AcquisitionStatus.Pending
                    };

                    dbContext.Repositories.Add(repo);
                    await dbContext.SaveChangesAsync(ct);
                }

                // Add source associations for every APIHunter key linked to this repository
                foreach (var rRef in refGroup)
                {
                    var existingSource = await dbContext.RepositorySources
                        .FirstOrDefaultAsync(rs => rs.RepositoryId == repo.Id && rs.ApiHunterRecordId == rRef.ApiHunterRecordId && rs.ApiHunterRepoRefId == rRef.SourceReferenceId, ct);

                    if (existingSource == null)
                    {
                        var source = new RepositorySource
                        {
                            RepositoryId = repo.Id,
                            DiscoveryType = DiscoveryType.ApiHunterSync,
                            ApiHunterRecordId = rRef.ApiHunterRecordId,
                            ApiHunterRepoRefId = rRef.SourceReferenceId,
                            DiscoveredViaQuery = $"APIHunter Record #{rRef.ApiHunterRecordId}"
                        };
                        dbContext.RepositorySources.Add(source);
                    }
                }


                await dbContext.SaveChangesAsync(ct);
                count++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error seeding repository {Owner}/{Name}", owner, name);
            }
        }

        await auditService.RecordAsync(
            AuditEventCode.BulkRepositoryAcquisitionTriggered,
            userId,
            null,
            "127.0.0.1",
            new { SeededRepositoriesCount = count },
            ct);

        return count;
    }

    public async Task<RepositorySnapshot> AcquireSnapshotAsync(Guid repositoryId, string? branch = null, CancellationToken ct = default)
    {
        var repo = await dbContext.Repositories.FirstOrDefaultAsync(r => r.Id == repositoryId, ct)
            ?? throw new KeyNotFoundException($"Repository {repositoryId} not found.");

        branch ??= repo.DefaultBranch;
        var commitSha = await repositoryProvider.GetLatestCommitShaAsync(repo.Owner, repo.Name, branch, ct);

        // Check if snapshot already exists
        var existingSnapshot = await dbContext.RepositorySnapshots
            .FirstOrDefaultAsync(s => s.RepositoryId == repositoryId && s.CommitSha == commitSha, ct);

        if (existingSnapshot != null && existingSnapshot.AnalysisStatus == AnalysisStatus.Completed)
        {
            logger.LogInformation("Snapshot for {FullName} commit {Commit} already exists and is completed.", repo.FullName, commitSha);
            return existingSnapshot;
        }

        logger.LogInformation("Acquiring tarball archive for {FullName} @ {Commit}...", repo.FullName, commitSha);
        await using var archiveStream = await repositoryProvider.DownloadArchiveAsync(repo.Owner, repo.Name, commitSha, ct);

        // Upload raw archive to ObjectStore
        var objectKey = $"repos/{repo.Id}/snapshots/{commitSha}.tar.gz";
        await objectStore.PutAsync(objectKey, archiveStream, "application/gzip", ct);

        // Download back for safe extraction & cataloging
        await using var downloadStream = await objectStore.GetAsync(objectKey, ct);
        await using var gzipStream = new GZipStream(downloadStream, CompressionMode.Decompress);

        var snapshot = existingSnapshot ?? new RepositorySnapshot
        {
            RepositoryId = repo.Id,
            CommitSha = commitSha,
            BranchName = branch,
            ArchiveObjectKey = objectKey,
            AnalysisStatus = AnalysisStatus.Pending,
            AcquiredAtUtc = DateTime.UtcNow
        };

        if (existingSnapshot == null)
        {
            dbContext.RepositorySnapshots.Add(snapshot);
            await dbContext.SaveChangesAsync(ct);
        }

        // Extract and catalog files
        var (fileCount, totalBytes, snapshotFiles) = await CatalogTarStreamAsync(snapshot.Id, gzipStream, ct);
        snapshot.FileCount = fileCount;
        snapshot.TotalSizeBytes = totalBytes;

        dbContext.SnapshotFiles.AddRange(snapshotFiles);
        repo.AcquisitionStatus = AcquisitionStatus.Acquired;
        repo.LastAcquiredAtUtc = DateTime.UtcNow;

        await dbContext.SaveChangesAsync(ct);

        // Queue follow-up SnapshotAnalysis job
        await jobOrchestrationService.CreateJobAsync(
            JobType.SnapshotAnalysis,
            "Snapshot",
            snapshot.Id,
            priority: 50,
            correlationId: Guid.NewGuid().ToString(),
            ct: ct);

        await auditService.RecordAsync(
            AuditEventCode.RepositoryAcquired,
            null,
            null,
            "system",
            new { RepositoryId = repo.Id, SnapshotId = snapshot.Id, CommitSha = commitSha, FileCount = fileCount },
            ct);

        return snapshot;
    }


    private async Task<(int FileCount, long TotalBytes, List<SnapshotFile> Files)> CatalogTarStreamAsync(
        Guid snapshotId,
        Stream tarStream,
        CancellationToken ct)
    {
        using var reader = new TarReader(tarStream);
        var files = new List<SnapshotFile>();
        int count = 0;
        long totalBytes = 0;
        var opts = options.Value;

        TarEntry? entry;
        while ((entry = await reader.GetNextEntryAsync(false, ct)) != null)
        {
            if (entry.EntryType == TarEntryType.Directory || entry.EntryType == TarEntryType.SymbolicLink || entry.EntryType == TarEntryType.HardLink)
            {
                continue;
            }

            var path = entry.Name;

            // Security Path Traversal Guard: Reject any entry containing '..' or invalid root
            if (path.Contains("..") || path.StartsWith('/') || path.StartsWith('\\'))
            {
                logger.LogWarning("Rejecting unsafe tarball path traversal entry: {Path}", path);
                continue;
            }

            // Strip root repository directory prefix generated by GitHub (e.g. 'owner-repo-sha/')
            var slashIndex = path.IndexOf('/');
            var relativePath = slashIndex >= 0 ? path[(slashIndex + 1)..] : path;
            if (string.IsNullOrWhiteSpace(relativePath)) continue;

            var fileName = Path.GetFileName(relativePath);
            var extension = Path.GetExtension(relativePath).ToLowerInvariant();
            var sizeBytes = entry.Length;

            // Calculate SHA-256 content hash safely
            using var entryStream = entry.DataStream;
            if (entryStream == null) continue;

            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashBytes = await sha256.ComputeHashAsync(entryStream, ct);
            var contentHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

            // File Classification
            bool isBinary = IsBinaryExtension(extension);
            bool isTooLarge = sizeBytes > (opts.MaxFileSizeMb * 1024 * 1024);
            bool isVendored = IsVendoredPath(relativePath);

            SkipReason? skipReason = null;
            if (isBinary) skipReason = SkipReason.Binary;
            else if (isTooLarge) skipReason = SkipReason.TooLarge;
            else if (isVendored) skipReason = SkipReason.VendoredLib;

            bool isSkipped = skipReason.HasValue;

            files.Add(new SnapshotFile
            {
                SnapshotId = snapshotId,
                FilePath = relativePath,
                FileName = fileName,
                FileExtension = string.IsNullOrEmpty(extension) ? null : extension,
                ContentHash = contentHash,
                SizeBytes = sizeBytes,
                IsAnalyzed = false,
                IsBinary = isBinary,
                IsSkipped = isSkipped,
                SkipReason = skipReason
            });

            count++;
            totalBytes += sizeBytes;
        }

        return (count, totalBytes, files);
    }

    private static (string Owner, string Name) ParseGitHubUrl(string url)
    {
        var match = Regex.Match(url, @"github\.com[/:]+([^/]+)/([^/\.]+)", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            throw new ArgumentException($"Invalid GitHub repository URL: {url}");
        }
        return (match.Groups[1].Value, match.Groups[2].Value);
    }

    private static bool IsBinaryExtension(string ext) =>
        ext is ".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp" or ".ico" or ".pdf" or ".zip" or ".tar" or ".gz" or ".exe" or ".dll" or ".so" or ".dylib" or ".bin" or ".woff" or ".woff2" or ".ttf" or ".eot";

    private static bool IsVendoredPath(string path) =>
        path.StartsWith("node_modules/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("vendor/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(".git/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("dist/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("build/", StringComparison.OrdinalIgnoreCase);
}
