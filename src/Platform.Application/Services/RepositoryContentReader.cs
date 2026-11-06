using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;

namespace Platform.Application.Services;

public sealed record RepositoryTextFile(string Path, string Content, long SizeBytes, bool IsConfiguration);

/// <summary>
/// Reads text files out of a snapshot archive for AI analysis. The archive is taken from the object
/// store when present, otherwise it is re-downloaded through the configured repository provider.
/// When snapshot file metadata is available, configuration and source files are prioritized so the
/// AI sees the highest-value files first. Binary, vendored, oversized and non-UTF8 files are skipped.
/// </summary>
public sealed class RepositoryContentReader(
    IObjectStore objectStore,
    IRepositoryProvider repositoryProvider,
    ILogger<RepositoryContentReader> logger)
{
    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".7z",
        ".exe", ".dll", ".so", ".dylib", ".bin", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
        ".mov", ".avi", ".class", ".jar", ".war", ".pyc", ".o", ".a", ".lock"
    };

    private static readonly HashSet<string> VendoredPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules/", "vendor/", ".git/", "dist/", "build/", "bin/", "obj/", "target/"
    };

    private static readonly HashSet<string> ConfigurationNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".env", ".env.local", ".env.production", ".env.development", ".env.example",
        "dockerfile", "docker-compose.yml", "docker-compose.yaml", "appsettings.json",
        "appsettings.development.json", "appsettings.production.json", "web.config",
        "application.properties", "application.yml", "application.yaml", "config.json",
        "config.yaml", "config.yml", "secrets.json", "credentials.json"
    };

    private static readonly HashSet<string> ConfigurationExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".env", ".json", ".yaml", ".yml", ".config", ".ini", ".toml", ".properties", ".xml", ".conf"
    };

    private static readonly HashSet<string> SourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".kts",
        ".rb", ".php", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala", ".sh", ".bash",
        ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".sql", ".tf", ".tfvars", ".hcl", ".gradle",
        ".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".sln", ".mk", ".pl", ".lua", ".dart"
    };

    public async Task<IReadOnlyList<RepositoryTextFile>> ReadTextFilesAsync(
        RepositorySnapshot snapshot,
        Repository repository,
        int maxFiles,
        long maxFileBytes,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(repository);

        var selectedPaths = SelectPaths(snapshot, maxFiles, maxFileBytes);

        var archive = await OpenArchiveAsync(snapshot, repository, ct).ConfigureAwait(false);
        if (archive is null)
        {
            logger.LogWarning("No archive is available for snapshot {SnapshotId}; continuing with empty file list.", snapshot.Id);
            return Array.Empty<RepositoryTextFile>();
        }

        var files = await ExtractAsync(archive, selectedPaths, maxFiles, maxFileBytes, ct).ConfigureAwait(false);

        // Legacy snapshots may have catalogued paths with a stripped root prefix that does not
        // match the archive. Fall back to a straight sequential read so AI analysis still runs.
        if (files.Count == 0 && selectedPaths is not null)
        {
            var fallbackArchive = await OpenArchiveAsync(snapshot, repository, ct).ConfigureAwait(false);
            if (fallbackArchive is not null)
            {
                files = await ExtractAsync(fallbackArchive, null, maxFiles, maxFileBytes, ct).ConfigureAwait(false);
            }
        }

        return files;
    }

    private async Task<List<RepositoryTextFile>> ExtractAsync(
        Stream archive,
        HashSet<string>? selectedPaths,
        int maxFiles,
        long maxFileBytes,
        CancellationToken ct)
    {
        var files = new List<RepositoryTextFile>();
        try
        {
            await using (archive)
            await using (var gzip = new GZipStream(archive, CompressionMode.Decompress))
            using (var tar = new TarReader(gzip))
            {
                TarEntry? entry;
                while ((entry = await tar.GetNextEntryAsync(false, ct).ConfigureAwait(false)) is not null)
                {
                    if (selectedPaths is null && files.Count >= maxFiles)
                        break;

                    if (entry.EntryType is TarEntryType.Directory or TarEntryType.SymbolicLink or TarEntryType.HardLink)
                        continue;

                    if (entry.DataStream is null || entry.Length <= 0 || entry.Length > maxFileBytes)
                        continue;

                    var path = NormalizePath(entry.Name);
                    if (string.IsNullOrWhiteSpace(path) || path.Contains("..", StringComparison.Ordinal))
                        continue;

                    if (IsVendored(path) || IsBinary(path))
                        continue;

                    if (selectedPaths is not null && !selectedPaths.Contains(path))
                        continue;

                    byte[] bytes;
                    using (var ms = new MemoryStream())
                    {
                        await entry.DataStream.CopyToAsync(ms, ct).ConfigureAwait(false);
                        bytes = ms.ToArray();
                    }

                    string content;
                    try
                    {
                        content = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                            .GetString(bytes);
                    }
                    catch (DecoderFallbackException)
                    {
                        continue;
                    }

                    if (content.IndexOf('\0') >= 0)
                        continue;

                    files.Add(new RepositoryTextFile(path, content, entry.Length, IsConfiguration(path)));

                    if (selectedPaths is not null && files.Count >= selectedPaths.Count)
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed reading repository archive for AI analysis.");
            throw;
        }

        return files;
    }

    private static HashSet<string>? SelectPaths(RepositorySnapshot snapshot, int maxFiles, long maxFileBytes)
    {
        if (snapshot.Files is null || snapshot.Files.Count == 0 || maxFiles <= 0)
            return null;

        var selected = snapshot.Files
            .Where(f => !f.IsBinary && !f.IsSkipped && f.SizeBytes > 0 && f.SizeBytes <= maxFileBytes)
            .Where(f => !IsVendored(f.FilePath) && !IsBinary(f.FilePath))
            .OrderBy(f => Priority(f.FilePath))
            .ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .Take(maxFiles)
            .Select(f => f.FilePath)
            .ToHashSet(StringComparer.Ordinal);

        return selected.Count == 0 ? null : selected;
    }

    private static int Priority(string path)
    {
        if (IsConfiguration(path))
            return 0;

        if (path.StartsWith(".github/", StringComparison.OrdinalIgnoreCase))
            return 1;

        var fileName = Path.GetFileName(path);
        if (SourceExtensions.Contains(Path.GetExtension(path)) ||
            fileName.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("Makefile", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        if (IsLowPriorityPath(path))
            return 3;

        return 2;
    }

    private static bool IsLowPriorityPath(string path) =>
        path.StartsWith("docs/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("doc/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("test/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/docs/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("__tests__/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/examples/", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("/samples/", StringComparison.OrdinalIgnoreCase);

    private async Task<Stream?> OpenArchiveAsync(RepositorySnapshot snapshot, Repository repository, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.ArchiveObjectKey))
        {
            try
            {
                if (await objectStore.ExistsAsync(snapshot.ArchiveObjectKey, ct).ConfigureAwait(false))
                    return await objectStore.GetAsync(snapshot.ArchiveObjectKey, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed reading archive {Key} from object store.", snapshot.ArchiveObjectKey);
            }
        }

        var owner = repository.Owner;
        var name = repository.Name;
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(name))
        {
            var slash = repository.FullName?.IndexOf('/') ?? -1;
            if (slash > 0)
            {
                owner = repository.FullName![..slash];
                name = repository.FullName[(slash + 1)..];
            }
        }

        if (string.IsNullOrWhiteSpace(owner) ||
            string.IsNullOrWhiteSpace(name) ||
            string.IsNullOrWhiteSpace(snapshot.CommitSha))
        {
            return null;
        }

        try
        {
            logger.LogInformation("Archive missing for snapshot {SnapshotId}; re-downloading {Owner}/{Name}@{Commit}.",
                snapshot.Id, owner, name, snapshot.CommitSha);
            return await repositoryProvider.DownloadArchiveAsync(owner, name, snapshot.CommitSha, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed re-downloading archive for snapshot {SnapshotId}.", snapshot.Id);
            return null;
        }
    }

    internal static string NormalizePath(string rawName)
    {
        var path = rawName.Replace('\\', '/').Trim();

        while (path.StartsWith("./", StringComparison.Ordinal))
            path = path[2..];

        return path.TrimStart('/');
    }

    internal static bool IsConfiguration(string path)
    {
        var fileName = Path.GetFileName(path);
        return ConfigurationNames.Contains(fileName) ||
               ConfigurationExtensions.Contains(Path.GetExtension(path));
    }

    private static bool IsBinary(string path) => BinaryExtensions.Contains(Path.GetExtension(path));

    private static bool IsVendored(string path)
    {
        foreach (var prefix in VendoredPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/" + prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
