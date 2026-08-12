using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class SnapshotService(IPlatformDbContext dbContext)
{
    public async Task<RepositorySnapshot?> GetSnapshotByIdAsync(Guid snapshotId, CancellationToken ct = default)
    {
        return await dbContext.RepositorySnapshots
            .Include(s => s.Repository)
            .FirstOrDefaultAsync(s => s.Id == snapshotId, ct);
    }

    public async Task<List<RepositorySnapshot>> GetSnapshotsByRepositoryIdAsync(Guid repositoryId, CancellationToken ct = default)
    {
        return await dbContext.RepositorySnapshots
            .Where(s => s.RepositoryId == repositoryId)
            .OrderByDescending(s => s.AcquiredAtUtc)
            .ToListAsync(ct);
    }

    public async Task<List<SnapshotFile>> GetSnapshotFilesAsync(Guid snapshotId, string? extensionFilter = null, bool? isAnalyzed = null, CancellationToken ct = default)
    {
        var query = dbContext.SnapshotFiles.Where(sf => sf.SnapshotId == snapshotId);

        if (!string.IsNullOrWhiteSpace(extensionFilter))
        {
            query = query.Where(sf => sf.FileExtension == extensionFilter);
        }

        if (isAnalyzed.HasValue)
        {
            query = query.Where(sf => sf.IsAnalyzed == isAnalyzed.Value);
        }

        return await query.OrderBy(sf => sf.FilePath).ToListAsync(ct);
    }

    /// <summary>
    /// Incremental Hash Comparison:
    /// Compares files in new snapshot B against previous snapshot A for the same repository.
    /// Returns files with matching ContentHash that can reuse previous scan results.
    /// </summary>
    public async Task<Dictionary<string, List<CandidateOccurrence>>> GetReusableOccurrencesForHashesAsync(
        Guid repositoryId,
        IEnumerable<string> contentHashes,
        CancellationToken ct = default)
    {
        var hashList = contentHashes.Distinct().ToList();
        if (hashList.Count == 0) return [];

        // Find analyzed files in previous snapshots of this repository matching the content hashes
        var previousFiles = await dbContext.SnapshotFiles
            .Where(sf => sf.Snapshot.RepositoryId == repositoryId && hashList.Contains(sf.ContentHash) && sf.IsAnalyzed)
            .Include(sf => sf.Occurrences)
            .ToListAsync(ct);

        var result = new Dictionary<string, List<CandidateOccurrence>>();
        foreach (var file in previousFiles)
        {
            if (!result.ContainsKey(file.ContentHash))
            {
                result[file.ContentHash] = file.Occurrences.ToList();
            }
        }

        return result;
    }
}
