using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Compatibility descriptor for the planned BugHunter integration.
/// Execution remains fail-closed until an authoritative upstream image/CLI/API,
/// authentication, output, cancellation, and artifact contract is verified.
/// </summary>
public sealed class BugHunterScanProvider(
    ILogger<BugHunterScanProvider> logger) : IBugHunterProvider
{
    public const string UnavailableCode = "BUGHUNTER_CONTRACT_UNAVAILABLE";

    public string ProviderKey => "bughunter";

    public Task<ScanStartResult> StartAsync(
        ScanExecutionRequest request,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        logger.LogWarning(
            "BugHunter execution for job '{ScanJobId}' was rejected because no authoritative provider contract is configured.",
            request.ScanJobId);

        return Task.FromResult(new ScanStartResult(
            Success: false,
            ExternalScanId: string.Empty,
            ErrorMessage: UnavailableCode));
    }

    public Task<ScanStatusResult> GetStatusAsync(
        string externalScanId,
        CancellationToken ct = default)
    {
        return Task.FromResult(new ScanStatusResult(
            ExternalScanId: externalScanId,
            Status: SecurityScanJobStatus.Blocked,
            ProgressPercent: 0,
            Message: UnavailableCode));
    }

    public Task<ScanResult> GetResultAsync(
        string externalScanId,
        CancellationToken ct = default)
    {
        return Task.FromResult(new ScanResult(
            ExternalScanId: externalScanId,
            Status: SecurityScanJobStatus.Blocked,
            ToolResults: Array.Empty<ToolExecutionResult>(),
            ArtifactReference: null,
            Summary: UnavailableCode));
    }

    public Task CancelAsync(string externalScanId, CancellationToken ct = default)
    {
        logger.LogInformation(
            "BugHunter cancellation for '{ExternalScanId}' required no action because the provider is unavailable.",
            externalScanId);
        return Task.CompletedTask;
    }
}
