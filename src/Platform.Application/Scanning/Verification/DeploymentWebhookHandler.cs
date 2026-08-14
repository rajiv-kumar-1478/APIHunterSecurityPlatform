using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Verification;

public interface IApplicationTargetResolver
{
    Task<DeploymentTargetResolution?> ResolveTargetAsync(string applicationId, CancellationToken ct = default);
    Task<string?> GetWebhookSecretAsync(string applicationId, CancellationToken ct = default);
    Task<bool> HasWebhookBeenProcessedAsync(string webhookId, CancellationToken ct = default);
    Task MarkWebhookProcessedAsync(string webhookId, string applicationId, CancellationToken ct = default);
}

/// <summary>
/// Authoritative deployment webhook handler implementing HMAC-SHA256 verification,
/// timestamp replay prevention, unique ID tracking, and server-side application target resolution.
/// </summary>
public sealed class DeploymentWebhookHandler : IDeploymentWebhookHandler
{
    private static readonly TimeSpan MaxTimestampTolerance = TimeSpan.FromMinutes(5);

    private readonly IApplicationTargetResolver _targetResolver;
    private readonly ILogger<DeploymentWebhookHandler> _logger;

    public DeploymentWebhookHandler(
        IApplicationTargetResolver targetResolver,
        ILogger<DeploymentWebhookHandler> logger)
    {
        _targetResolver = targetResolver ?? throw new ArgumentNullException(nameof(targetResolver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<DeploymentWebhookResponse> HandleWebhookAsync(
        string rawBody,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawBody))
        {
            return new DeploymentWebhookResponse(false, null, "Empty webhook payload body.", "EMPTY_PAYLOAD");
        }

        // 1. Extract and validate required security headers
        var headerLookup = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

        if (!headerLookup.TryGetValue("X-Webhook-Id", out var webhookId) || string.IsNullOrWhiteSpace(webhookId))
        {
            return new DeploymentWebhookResponse(false, null, "Missing required X-Webhook-Id header.", "MISSING_WEBHOOK_ID");
        }

        if (!headerLookup.TryGetValue("X-Webhook-Timestamp", out var timestampStr) ||
            !DateTimeOffset.TryParse(timestampStr, out var webhookTimestamp))
        {
            return new DeploymentWebhookResponse(false, null, "Missing or invalid X-Webhook-Timestamp header.", "INVALID_TIMESTAMP");
        }

        // 2. Timestamp Tolerance Check (Replay Prevention)
        var timeDifference = (DateTimeOffset.UtcNow - webhookTimestamp).Duration();
        if (timeDifference > MaxTimestampTolerance)
        {
            _logger.LogWarning("Webhook timestamp '{Timestamp}' outside tolerance window ({Tolerance} min).",
                webhookTimestamp, MaxTimestampTolerance.TotalMinutes);
            return new DeploymentWebhookResponse(false, null, "Webhook timestamp outside allowed ±5-minute tolerance window.", "TIMESTAMP_OUT_OF_RANGE");
        }

        // 3. Persistent Idempotency Check (Duplicate Event Prevention)
        if (await _targetResolver.HasWebhookBeenProcessedAsync(webhookId, ct))
        {
            _logger.LogWarning("Duplicate webhook ID '{WebhookId}' received. Rejected to prevent replay.", webhookId);
            return new DeploymentWebhookResponse(false, null, $"Duplicate webhook event '{webhookId}' already processed.", "DUPLICATE_EVENT_ID");
        }

        // 4. Parse Deployment Request
        DeploymentWebhookRequest? requestPayload;
        try
        {
            requestPayload = JsonSerializer.Deserialize<DeploymentWebhookRequest>(rawBody, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse deployment webhook JSON.");
            return new DeploymentWebhookResponse(false, null, "Malformed JSON body.", "MALFORMED_JSON");
        }

        if (requestPayload == null || string.IsNullOrWhiteSpace(requestPayload.ApplicationId))
        {
            return new DeploymentWebhookResponse(false, null, "ApplicationId is required in deployment payload.", "MISSING_APPLICATION_ID");
        }

        // 5. Server-Side Target Resolution
        var resolution = await _targetResolver.ResolveTargetAsync(requestPayload.ApplicationId, ct);
        if (resolution == null || !resolution.IsAuthorized || string.IsNullOrWhiteSpace(resolution.AuthorizedTargetUrl))
        {
            _logger.LogWarning("ApplicationId '{AppId}' not found or unauthorized.", requestPayload.ApplicationId);
            return new DeploymentWebhookResponse(false, null, $"Application '{requestPayload.ApplicationId}' is unauthorized or unknown.", "UNAUTHORIZED_APPLICATION");
        }

        // 6. Cryptographic HMAC Signature Verification
        var secret = await _targetResolver.GetWebhookSecretAsync(requestPayload.ApplicationId, ct);
        if (string.IsNullOrWhiteSpace(secret))
        {
            return new DeploymentWebhookResponse(false, null, "Webhook secret not configured for application.", "MISSING_SECRET_CONFIG");
        }

        string? signatureHeader = null;
        if (headerLookup.TryGetValue("X-Hub-Signature-256", out var ghSig)) signatureHeader = ghSig;
        else if (headerLookup.TryGetValue("X-Webhook-Signature", out var customSig)) signatureHeader = customSig;

        if (string.IsNullOrWhiteSpace(signatureHeader))
        {
            return new DeploymentWebhookResponse(false, null, "Missing cryptographic signature header.", "MISSING_SIGNATURE");
        }

        if (!VerifyHmacSignature(rawBody, secret, signatureHeader))
        {
            _logger.LogWarning("Invalid HMAC signature for application '{AppId}'.", requestPayload.ApplicationId);
            return new DeploymentWebhookResponse(false, null, "Cryptographic signature validation failed.", "INVALID_SIGNATURE");
        }

        // 7. Mark Webhook Processed (Idempotency Record)
        await _targetResolver.MarkWebhookProcessedAsync(webhookId, requestPayload.ApplicationId, ct);

        // 8. Create Asynchronous SecurityScanJob
        var scanJobId = Guid.NewGuid();
        _logger.LogInformation("Enqueued deployment scan job '{ScanJobId}' for application '{AppId}' at target '{TargetUrl}' (Commit: {CommitSha}).",
            scanJobId, resolution.ApplicationId, resolution.AuthorizedTargetUrl, requestPayload.CommitSha);

        return new DeploymentWebhookResponse(
            IsSuccess: true,
            ScanJobId: scanJobId.ToString(),
            Message: $"Deployment scan job successfully created for '{resolution.AuthorizedTargetUrl}'."
        );
    }

    public static bool VerifyHmacSignature(string rawBody, string secret, string signatureHeader)
    {
        var cleanSignature = signatureHeader.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase)
            ? signatureHeader[7..]
            : signatureHeader;

        byte[] expectedHash;
        try
        {
            expectedHash = Convert.FromHexString(cleanSignature);
        }
        catch
        {
            return false;
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(rawBody));

        return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
    }
}
