using System;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable, cryptographically verifiable audit record capturing the full provenance,
/// registry snapshot, tool manifests, selection policy, and PlanHash for a scan job.
/// </summary>
public class ScanPlanAuditRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ScanJobId { get; set; }
    public Guid TenantId { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public string TargetKind { get; set; } = string.Empty;
    public string Profile { get; set; } = string.Empty;
    public string PlanHash { get; set; } = string.Empty;
    public string PlannerVersion { get; set; } = string.Empty;
    public string RegistrySnapshotHash { get; set; } = string.Empty;
    public string ExecutionSequenceJson { get; set; } = "[]";
    public string SelectionReasonsJson { get; set; } = "{}";
    public string RuleSetVersionsJson { get; set; } = "{}";
    public string ToolManifestSnapshotsJson { get; set; } = "[]";
    public string CapabilitySnapshotJson { get; set; } = "[]";
    public string SelectionPolicySnapshotJson { get; set; } = "{}";
    public string PreviousAuditHash { get; set; } = string.Empty;
    public string RecordHash { get; set; } = string.Empty;
    public DateTime PlannedAtUtc { get; set; } = DateTime.UtcNow;
}
