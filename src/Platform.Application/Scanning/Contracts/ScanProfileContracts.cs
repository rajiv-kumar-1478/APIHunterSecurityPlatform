using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Resource requirements specification for a security scan tool.
/// </summary>
public record ScanToolResourceRequirements(
    double CpuCores,
    long MemoryBytes,
    long ScratchBytes,
    TimeSpan Timeout
);

/// <summary>
/// Machine-readable tool capability contract (Contract Version 1.0).
/// Defines authoritative metadata, capabilities, supported execution profiles, required RBAC permissions,
/// output formats, and resource bounds.
/// </summary>
public record ScanToolCapabilityContract(
    string ToolKey,
    string DisplayName,
    string Version,
    IReadOnlyList<ToolCapability> Capabilities,
    IReadOnlyList<SecurityScanProfileType> SupportedProfiles,
    IReadOnlyList<string> RequiredPermissions,
    IReadOnlyList<ToolOutputFormat> OutputFormats,
    ScanToolResourceRequirements ResourceRequirements,
    string ContractVersion = "1.0"
);

/// <summary>
/// Canonical scan execution profile definition.
/// Defines required vs optional capabilities, maximum resource ceilings, and execution purpose.
/// </summary>
public record ScanProfileDefinition(
    SecurityScanProfileType Profile,
    string CanonicalName,
    string Description,
    IReadOnlyList<ToolCapability> RequiredCapabilities,
    IReadOnlyList<ToolCapability> OptionalCapabilities,
    ScanToolResourceRequirements MaximumAllowableLimits
);

/// <summary>
/// Result codes for tool-to-profile compatibility evaluations.
/// </summary>
public enum ToolProfileCompatibilityResult
{
    Compatible,
    ProfileNotSupported,
    MissingRequiredCapability,
    MissingMachineParseableOutputFormat,
    ExceedsCpuLimit,
    ExceedsMemoryLimit,
    ExceedsScratchLimit,
    ExceedsTimeoutLimit
}

/// <summary>
/// Detailed evaluation verdict for tool compatibility against a scan profile.
/// </summary>
public record ToolCompatibilityEvaluation(
    string ToolKey,
    SecurityScanProfileType Profile,
    bool IsCompatible,
    ToolProfileCompatibilityResult Code,
    string Reason
);
