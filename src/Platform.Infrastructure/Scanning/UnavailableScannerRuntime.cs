using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Fail-closed scanner runtime used when no production executor and enforced egress
/// boundary have been configured. It never invokes a host process or container.
/// </summary>
public sealed class UnavailableScannerRuntime(
    ILogger<UnavailableScannerRuntime> logger) : IScannerRuntimeSandbox
{
    public const string ErrorCode = "SCANNER_RUNTIME_DISABLED";

    public Task<ToolExecutionResult> ExecuteInSandboxAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(egressTarget);
        ArgumentNullException.ThrowIfNull(secretLease);

        logger.LogWarning(
            "Scanner execution for job '{ScanJobId}' and tool '{ToolKey}' was rejected because the scanner runtime is disabled.",
            request.ScanJobId,
            request.ToolKey);

        return Task.FromResult(new ToolExecutionResult(
            request.ToolKey,
            request.Version,
            cancellationToken.IsCancellationRequested
                ? ToolExecutionStatus.Cancelled
                : ToolExecutionStatus.Failed,
            ExitCode: -1,
            ArtifactReference: null,
            ErrorCode: cancellationToken.IsCancellationRequested ? "EXECUTION_CANCELLED" : ErrorCode,
            FailureClassification: cancellationToken.IsCancellationRequested
                ? ToolFailureClassification.Cancelled
                : ToolFailureClassification.SecurityBoundary));
    }
}
