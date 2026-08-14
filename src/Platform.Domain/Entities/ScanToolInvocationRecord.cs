using System;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable execution record for an individual scanner tool invocation within a scan job.
/// Captures granular lifecycle timing, exit code, resource coverage, error states, and cryptographic provenance.
/// </summary>
public class ScanToolInvocationRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ScanJobId { get; set; }
    public Guid TenantId { get; set; }
    public string ToolKey { get; set; } = string.Empty;
    public string ToolVersion { get; set; } = string.Empty;
    public string ContainerImageDigest { get; set; } = string.Empty;
    public string RuleSetVersion { get; set; } = string.Empty;
    public string PlanHash { get; set; } = string.Empty;
    public string RegistrySnapshotHash { get; set; } = string.Empty;
    public string ExecutionPhase { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";
    public int ExitCode { get; set; }
    public long DurationMs { get; set; }
    public int CandidateCount { get; set; }
    public string CoverageJson { get; set; } = "{}";
    public string? ErrorMessage { get; set; }
    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }
}
