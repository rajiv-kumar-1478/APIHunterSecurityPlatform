using System.Diagnostics;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Adapters.ObjectStore;

public class S3ObjectStoreAdapter : IObjectStore
{
    private readonly AmazonS3Client _s3Client;
    private readonly string _bucketName;
    private readonly ILogger<S3ObjectStoreAdapter> _logger;

    public S3ObjectStoreAdapter(
        IOptions<ObjectStoreOptions> options,
        ILogger<S3ObjectStoreAdapter> logger)
    {
        _logger = logger;
        var opts = options.Value;
        _bucketName = opts.BucketName;

        var credentials = new BasicAWSCredentials(opts.AccessKeyId, opts.SecretAccessKey);
        var config = new AmazonS3Config
        {
            ServiceURL = opts.ServiceUrl,
            AuthenticationRegion = string.IsNullOrWhiteSpace(opts.Region) ? "auto" : opts.Region,
            ForcePathStyle = true
        };

        _s3Client = new AmazonS3Client(credentials, config);
    }

    public async Task<string> PutAsync(string key, Stream content, string? contentType = null, CancellationToken ct = default)
    {
        var request = new PutObjectRequest
        {
            BucketName = _bucketName,
            Key = key,
            InputStream = content,
            ContentType = contentType ?? "application/octet-stream",
            DisablePayloadSigning = true,
            DisableDefaultChecksumValidation = true
        };

        await _s3Client.PutObjectAsync(request, ct);
        _logger.LogInformation("Uploaded object to S3/R2 store: {Bucket}/{Key}", _bucketName, key);
        return key;
    }

    public async Task<Stream> GetAsync(string key, CancellationToken ct = default)
    {
        var request = new GetObjectRequest
        {
            BucketName = _bucketName,
            Key = key
        };

        var response = await _s3Client.GetObjectAsync(request, ct);
        return response.ResponseStream;
    }

    public async Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var request = new DeleteObjectRequest
        {
            BucketName = _bucketName,
            Key = key
        };

        await _s3Client.DeleteObjectAsync(request, ct);
        _logger.LogInformation("Deleted object from S3/R2 store: {Bucket}/{Key}", _bucketName, key);
    }

    public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
    {
        try
        {
            await _s3Client.GetObjectMetadataAsync(_bucketName, key, ct);
            return true;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    public async Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var exists = await Amazon.S3.Util.AmazonS3Util.DoesS3BucketExistV2Async(_s3Client, _bucketName);
            sw.Stop();

            return new ComponentHealthResult("S3ObjectStore", exists, exists ? "Healthy" : "Degraded", $"Bucket: {_bucketName}", sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            _logger.LogError(ex, "S3/R2 ObjectStore health check failed.");
            return new ComponentHealthResult("S3ObjectStore", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }
}

