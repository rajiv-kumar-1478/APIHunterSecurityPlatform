using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Execution.Contracts;

public enum ToolInvocationStatus
{
    Pending = 1,
    Running = 2,
    Completed = 3,
    Failed = 4,
    TimedOut = 5,
    Skipped = 6
}

public enum OverallScanExecutionStatus
{
    Running = 1,
    Completed = 2,
    CompletedWithToolFailures = 3,
    Failed = 4,
    Cancelled = 5,
    TimedOut = 6
}

public sealed record ToolInvocationDetailDto(
    Guid InvocationId,
    string ToolKey,
    string ToolVersion,
    string ContainerImageDigest,
    string RuleSetVersion,
    string ExecutionPhase,
    ToolInvocationStatus Status,
    int ExitCode,
    long DurationMs,
    int CandidateCount,
    ScannerCoverage? Coverage,
    string? ErrorMessage,
    DateTime StartedAtUtc,
    DateTime? CompletedAtUtc
);

public sealed record ScanJobExecutionSummaryDto(
    Guid ScanJobId,
    Guid TenantId,
    string PlanHash,
    string RegistrySnapshotHash,
    OverallScanExecutionStatus OverallStatus,
    int TotalToolsPlanned,
    int ToolsCompleted,
    int ToolsFailed,
    int TotalFindingsIngested,
    long TotalExecutionDurationMs,
    IReadOnlyList<ToolInvocationDetailDto> Invocations
);

public sealed record PlanExecutionResult(
    Guid ScanJobId,
    OverallScanExecutionStatus OverallStatus,
    int TotalFindingsIngested,
    IReadOnlyList<FindingCandidate> IngestedCandidates,
    IReadOnlyList<ToolInvocationDetailDto> Invocations,
    long TotalDurationMs
);
