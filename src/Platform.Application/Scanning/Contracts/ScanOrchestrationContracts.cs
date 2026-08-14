using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Execution phases for scan profile tool orchestration.
/// Explicit execution order: Discovery -> Probing -> Assessment -> Ingestion.
/// </summary>
public enum ScanExecutionPhase
{
    Discovery = 1,
    Probing = 2,
    Assessment = 3,
    Ingestion = 4
}

/// <summary>
/// Per-tool execution receipt recording immutable provenance, runtime metrics, output stats, and finding ingestion results.
/// </summary>
public record ToolExecutionReceipt(
    string ToolKey,
    string Version,
    string? Executable,
    string? ContainerImageRepository,
    string? ContainerImageDigest,
    SecurityScanProfileType Profile,
    ScanExecutionPhase Phase,
    ToolExecutionStatus Status,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    long DurationMs,
    long OutputSizeBytes,
    int CandidatesParsed,
    int FindingsCreated,
    int FindingsUpdated,
    string? FailureReason = null,
    ToolFailureClassification FailureClassification = ToolFailureClassification.None
);

/// <summary>
/// Comprehensive scan execution receipt detailing the complete multi-tool pipeline outcome.
/// </summary>
public record ScanExecutionReceipt(
    Guid JobId,
    SecurityScanProfileType Profile,
    SecurityScanJobStatus FinalJobStatus,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    IReadOnlyList<ToolExecutionReceipt> ToolReceipts,
    int TotalFindingsCreated,
    int TotalFindingsUpdated,
    string Summary
);

/// <summary>
/// Enriched scan job detail DTO for dashboard inspection, live tracking, and receipt review.
/// </summary>
public record ScanJobDetailDto(
    Guid Id,
    Guid? RepositoryId,
    string? RepositoryName,
    Guid? TargetId,
    string? TargetName,
    string TargetUrl,
    SecurityScanProfileType ScanProfile,
    SecurityScanJobStatus Status,
    string ProviderKey,
    string CorrelationId,
    int ProgressPercentage,
    string? CurrentPhase,
    string? CurrentTool,
    int TotalFindingsCount,
    DateTime CreatedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    DateTime? CancelledAtUtc,
    string? FailureReason,
    Guid? RetryOfJobId,
    int Version,
    ScanExecutionReceipt? ExecutionReceipt
);

/// <summary>
/// Callback contract for real-time scan progress reporting during orchestrator execution.
/// </summary>
public interface IScanProgressReporter
{
    Task ReportProgressAsync(
        Guid jobId,
        int progressPercentage,
        ScanExecutionPhase? phase,
        string? currentTool,
        int findingsDiscoveredSoFar,
        CancellationToken ct = default);
}
