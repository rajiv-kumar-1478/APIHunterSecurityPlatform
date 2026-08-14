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
    string? FailureReason = null
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
