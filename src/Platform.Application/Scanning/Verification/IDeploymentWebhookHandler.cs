using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Verification;

public sealed record DeploymentWebhookResponse(
    bool IsSuccess,
    string? ScanJobId,
    string? Message,
    string? ErrorCode = null
);

/// <summary>
/// Authoritative deployment webhook handler with constant-time HMAC validation,
/// timestamp replay protection, idempotency enforcement, and server-side target resolution.
/// </summary>
public interface IDeploymentWebhookHandler
{
    /// <summary>
    /// Validates signed CI/CD webhook requests and enqueues an asynchronous incremental scan job.
    /// </summary>
    Task<DeploymentWebhookResponse> HandleWebhookAsync(
        string rawBody,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct = default);
}
