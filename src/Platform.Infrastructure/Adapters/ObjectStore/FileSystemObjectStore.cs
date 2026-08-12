using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.ObjectStore;

public class FileSystemObjectStore : IObjectStore
{
    private readonly string _basePath;
    private readonly ILogger<FileSystemObjectStore> _logger;

    public FileSystemObjectStore(
        IHostEnvironment environment,
        IOptions<ObjectStoreOptions> options,
        ILogger<FileSystemObjectStore> logger)
    {
        _logger = logger;

        // Security Guard: Refuse to run FileSystem storage in Production environment!
        if (environment.IsProduction())
        {
            throw new InvalidOperationException(
                "FileSystemObjectStore is restricted to Development environments. " +
                "Production environments must configure external S3/R2 storage (ObjectStore:Provider = 'S3').");
        }

        _basePath = Path.GetFullPath(options.Value.BasePath);
        if (!Directory.Exists(_basePath))
        {
            Directory.CreateDirectory(_basePath);
        }
    }

    public async Task<string> PutAsync(string key, Stream content, string? contentType = null, CancellationToken ct = default)
    {
        var filePath = GetFullPath(key);
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        await using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);
        await content.CopyToAsync(fileStream, ct);

        _logger.LogInformation("Saved object to FileSystem: {Key}", key);
        return key;
    }

    public Task<Stream> GetAsync(string key, CancellationToken ct = default)
    {
        var filePath = GetFullPath(key);
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Object key not found in FileSystem store: {key}", filePath);
        }

        Stream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, true);
        return Task.FromResult(stream);
    }


    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var filePath = GetFullPath(key);
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            _logger.LogInformation("Deleted object from FileSystem: {Key}", key);
        }
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
    {
        var filePath = GetFullPath(key);
        return Task.FromResult(File.Exists(filePath));
    }

    public Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var exists = Directory.Exists(_basePath);
            sw.Stop();
            return Task.FromResult(new ComponentHealthResult("FileSystemObjectStore", exists, exists ? "Healthy" : "Degraded", $"Path: {_basePath}", sw.Elapsed));
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Task.FromResult(new ComponentHealthResult("FileSystemObjectStore", false, "Unhealthy", ex.Message, sw.Elapsed));
        }
    }

    private string GetFullPath(string key)
    {
        // Path traversal protection
        var safeKey = key.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(Path.Combine(_basePath, safeKey));

        if (!fullPath.StartsWith(_basePath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Path traversal attempt rejected for key: {key}");
        }

        return fullPath;
    }
}
