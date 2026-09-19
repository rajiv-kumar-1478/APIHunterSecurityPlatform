using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Verification;

namespace Platform.Api.Controllers;

/// <summary>
/// Public HMAC-authenticated endpoint for CI/CD deployment webhook delivery.
///
/// Authentication model: This endpoint is intentionally anonymous — it is not protected
/// by the browser cookie or CSRF token because CI/CD systems cannot obtain a session
/// cookie. Authentication is provided exclusively by the per-application HMAC-SHA256
/// signature (<c>X-Hub-Signature-256</c> or <c>X-Webhook-Signature</c>) verified
/// inside <see cref="IDeploymentWebhookHandler"/>.
///
/// Rate limiting, IP restrictions, and signing-key rotation are the operator's
/// responsibility at the infrastructure layer (reverse proxy / gateway).
/// </summary>
[ApiController]
[Route("api/v1/webhooks")]
[AllowAnonymous] // Auth is HMAC-based, not cookie/CSRF.
public class DeploymentWebhookController : ControllerBase
{
    private readonly IDeploymentWebhookHandler _webhookHandler;
    private readonly ILogger<DeploymentWebhookController> _logger;

    public DeploymentWebhookController(
        IDeploymentWebhookHandler webhookHandler,
        ILogger<DeploymentWebhookController> logger)
    {
        _webhookHandler = webhookHandler ?? throw new ArgumentNullException(nameof(webhookHandler));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Accepts an HMAC-signed deployment event from a CI/CD system, validates it,
    /// and enqueues an incremental security scan job for the registered application.
    /// </summary>
    /// <remarks>
    /// Required headers:
    /// <list type="bullet">
    ///   <item><c>X-Webhook-Id</c> — Unique delivery ID (used for idempotency).</item>
    ///   <item><c>X-Webhook-Timestamp</c> — ISO 8601 timestamp (±5-minute tolerance).</item>
    ///   <item><c>X-Hub-Signature-256</c> or <c>X-Webhook-Signature</c> — HMAC-SHA256 of the raw body prefixed with <c>sha256=</c>.</item>
    /// </list>
    ///
    /// The target URL is resolved entirely server-side from the <c>applicationId</c> in the payload.
    /// Caller-supplied URLs are always rejected.
    /// </remarks>
    /// <returns>
    /// 200 OK with <c>scanJobId</c> on success.<br/>
    /// 400 Bad Request on invalid payload / missing headers.<br/>
    /// 401 Unauthorized on invalid HMAC signature or unknown application.<br/>
    /// 409 Conflict on duplicate webhook delivery.<br/>
    /// 500 Internal Server Error if scan-job enqueue fails (webhook remains retryable).
    /// </returns>
    [HttpPost("deployments")]
    [Consumes("application/json")]
    [Produces("application/json")]
    [IgnoreAntiforgeryToken] // Explicit: HMAC replaces CSRF for this machine-to-machine endpoint.
    public async Task<IActionResult> HandleDeploymentWebhook(CancellationToken ct)
    {
        // Read raw body for HMAC verification — must happen before model binding.
        string rawBody;
        try
        {
            using var reader = new StreamReader(Request.Body);
            rawBody = await reader.ReadToEndAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read deployment webhook request body.");
            return BadRequest(new { code = "UNREADABLE_BODY", message = "Could not read request body." });
        }

        // Build a header dictionary from the incoming request.
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in Request.Headers)
        {
            if (header.Value.Count > 0)
            {
                headers[header.Key] = header.Value.ToString();
            }
        }

        var result = await _webhookHandler.HandleWebhookAsync(rawBody, headers, ct);

        if (result.IsSuccess)
        {
            return Ok(new
            {
                scanJobId = result.ScanJobId,
                message = result.Message
            });
        }

        // Map error codes to appropriate HTTP status codes.
        return result.ErrorCode switch
        {
            "DUPLICATE_EVENT_ID" => Conflict(new { code = result.ErrorCode, message = result.Message }),
            "UNAUTHORIZED_APPLICATION" or "INVALID_SIGNATURE" or "MISSING_SIGNATURE" or "MISSING_SECRET_CONFIG"
                => Unauthorized(new { code = result.ErrorCode, message = result.Message }),
            "TIMESTAMP_OUT_OF_RANGE" or "INVALID_TIMESTAMP" or "MISSING_WEBHOOK_ID"
                or "EMPTY_PAYLOAD" or "MALFORMED_JSON" or "MISSING_APPLICATION_ID"
                => BadRequest(new { code = result.ErrorCode, message = result.Message }),
            "SCAN_JOB_ENQUEUE_FAILED"
                => StatusCode(500, new { code = result.ErrorCode, message = result.Message }),
            _ => BadRequest(new { code = result.ErrorCode ?? "WEBHOOK_ERROR", message = result.Message })
        };
    }

    /// <summary>
    /// Health probe for the webhook endpoint. Anonymous and does not require a signature.
    /// Returns 200 if the endpoint is reachable.
    /// </summary>
    [HttpGet("deployments/ping")]
    public IActionResult Ping()
    {
        return Ok(new { status = "webhook_endpoint_online", utc = DateTime.UtcNow });
    }
}
