using System;
using System.Collections.Generic;

namespace Platform.Application.Scanning.Audit.Contracts;

public sealed record ToolManifestAuditSnapshot(
    string ToolKey,
    string Version,
    string ContainerImageDigest,
    IReadOnlyList<string> Capabilities,
    string ExecutionPhase,
    string ParserVersion,
    string ManifestVersion
);

public sealed record ScanProvenanceResponse(
    Guid ScanJobId,
    Guid TenantId,
    string TargetUrl,
    string TargetKind,
    string Profile,
    string PlanHash,
    string PlannerVersion,
    string RegistrySnapshotHash,
    IReadOnlyList<string> ExecutionSequence,
    IReadOnlyDictionary<string, string> RuleSetVersions,
    IReadOnlyDictionary<string, string> SelectionReasons,
    IReadOnlyList<ToolManifestAuditSnapshot> ToolManifestSnapshots,
    string PreviousAuditHash,
    string RecordHash,
    DateTime PlannedAtUtc
);
