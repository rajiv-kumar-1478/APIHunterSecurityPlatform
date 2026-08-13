using System;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityScanTool
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string ToolKey { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Version { get; set; } = "unverified";

    public string Executable { get; set; } = string.Empty;

    public string ImageReference { get; set; } = string.Empty;

    public string ImageDigest { get; set; } = string.Empty;

    public string ArtifactSourceType { get; set; } = string.Empty;

    public string ArtifactRepository { get; set; } = string.Empty;

    public string ArtifactUrl { get; set; } = string.Empty;

    public string ArtifactSha256 { get; set; } = string.Empty;

    public string ArtifactFormat { get; set; } = "binary"; // binary, zip, tar.gz

    public string CapabilityProbeCommand { get; set; } = "--help";

    public string CapabilityProbeExpectedKeyword { get; set; } = string.Empty;

    public string? ArtifactSignature { get; set; }

    public string? ContainerImageDigest { get; set; }

    public bool Enabled { get; set; } = true;

    public bool Required { get; set; } = false;

    public string CapabilitiesJson { get; set; } = "[]";

    public ToolHealthStatus HealthStatus { get; set; } = ToolHealthStatus.Healthy;

    public DateTime? LastHealthCheckUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
