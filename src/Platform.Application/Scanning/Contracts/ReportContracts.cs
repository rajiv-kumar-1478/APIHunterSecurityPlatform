using System;
using System.Collections.Generic;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

public enum SecurityReportFormat
{
    Json,
    Sarif,
    Markdown,
    Html
}

public static class ReportResourceBounds
{
    public const int MaxReportFindings = 1000;
    public const int MaxEvidenceItemsPerFinding = 20;
    public const int MaxTotalEvidencePayloadBytes = 10 * 1024 * 1024; // 10 MiB
    public const int MaxReportOutputBytes = 20 * 1024 * 1024; // 20 MiB
}

public sealed record ReportMetadata(
    Guid ReportId,
    string SignatureVersion,
    Guid ScanJobId,
    Guid TenantId,
    Guid? TargetId,
    string RepositoryName,
    string TargetUrl,
    SecurityScanProfileType ScanProfile,
    SecurityScanJobStatus JobStatus,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    DateTime GeneratedAtUtc,
    long DurationMs,
    string ToolCoverageHash,
    string ProvenanceSignature
);

public sealed record ExecutivePostureSummary(
    double AggregateRiskScore,
    RiskSeverity RiskRating,
    int TotalFindings,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount,
    int InfoCount,
    IReadOnlyDictionary<string, int> OwaspTop10Distribution,
    IReadOnlyDictionary<string, int> CweTop25Distribution
);

public sealed record SanitizedEvidenceItem(
    string EvidenceFingerprint,
    string EvidenceReference,
    string SafeEvidenceJson,
    DateTime CreatedAtUtc
);

public sealed record ReportRemediationItem(
    RemediationActionType ActionType,
    RemediationActionStatus Status,
    string Title,
    string Description,
    string ProviderKey,
    string ProviderResourceReference
);

public sealed record ReportFindingItem(
    string FindingFingerprint,
    string Title,
    string Description,
    FindingType FindingType,
    RiskSeverity Severity,
    double RiskScore,
    FindingConfidence Confidence,
    FindingStatus Status,
    DateTime FirstObservedAtUtc,
    DateTime LastObservedAtUtc,
    IReadOnlyList<string> CveList,
    IReadOnlyList<string> CweList,
    double? CvssScore,
    IReadOnlyList<SanitizedEvidenceItem> SanitizedEvidences,
    ReportRemediationItem? RecommendedRemediation
);

public sealed record CanonicalSecurityReport(
    ReportMetadata Metadata,
    ExecutivePostureSummary PostureSummary,
    IReadOnlyList<ReportFindingItem> Findings,
    ScanResultSummary ScanSummary,
    ScanDiff? ScanDiff,
    IReadOnlyList<ToolExecutionReceipt> ToolReceipts
);

public sealed record FormattedReportResult(
    string Content,
    string ContentType,
    string FileName
);
