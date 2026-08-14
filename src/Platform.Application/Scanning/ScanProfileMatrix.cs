using System;
using System.Collections.Generic;
using System.Linq;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning;

/// <summary>
/// Authoritative, deterministic registry for scan execution profiles and tool capability validation.
/// Defines required/optional capabilities, maximum resource bounds, and compatibility evaluation rules.
/// </summary>
public static class ScanProfileMatrix
{
    private static readonly ScanProfileDefinition ReconProfile = new(
        Profile: SecurityScanProfileType.Recon,
        CanonicalName: "Recon",
        Description: "Fast, low-impact reconnaissance, subdomain enumeration, and DNS probing",
        RequiredCapabilities: new[]
        {
            ToolCapability.SubdomainEnumeration,
            ToolCapability.DnsResolution,
            ToolCapability.HttpProbing
        },
        OptionalCapabilities: new[]
        {
            ToolCapability.SecretScanning
        },
        MaximumAllowableLimits: new ScanToolResourceRequirements(
            CpuCores: 1.0,
            MemoryBytes: 536_870_912, // 512 MiB
            ScratchBytes: 268_435_456, // 256 MiB
            Timeout: TimeSpan.FromMinutes(10)
        )
    );

    private static readonly ScanProfileDefinition StandardProfile = new(
        Profile: SecurityScanProfileType.Standard,
        CanonicalName: "Standard",
        Description: "Core vulnerability assessment, active crawling, and security misconfiguration detection",
        RequiredCapabilities: new[]
        {
            ToolCapability.HttpProbing,
            ToolCapability.UrlCrawling,
            ToolCapability.VulnerabilityScanning
        },
        OptionalCapabilities: new[]
        {
            ToolCapability.DnsResolution,
            ToolCapability.SecretScanning
        },
        MaximumAllowableLimits: new ScanToolResourceRequirements(
            CpuCores: 2.0,
            MemoryBytes: 1_073_741_824, // 1 GiB
            ScratchBytes: 536_870_912,  // 512 MiB
            Timeout: TimeSpan.FromMinutes(20)
        )
    );

    private static readonly ScanProfileDefinition DeepProfile = new(
        Profile: SecurityScanProfileType.Deep,
        CanonicalName: "Deep",
        Description: "Comprehensive multi-vector vulnerability scanning, active fuzzing, and AI-assisted hunting",
        RequiredCapabilities: new[]
        {
            ToolCapability.SubdomainEnumeration,
            ToolCapability.DnsResolution,
            ToolCapability.HttpProbing,
            ToolCapability.UrlCrawling,
            ToolCapability.VulnerabilityScanning,
            ToolCapability.Fuzzing,
            ToolCapability.AiAssistedHunting,
            ToolCapability.ReportGeneration
        },
        OptionalCapabilities: new[]
        {
            ToolCapability.SecretScanning,
            ToolCapability.Web3Analysis
        },
        MaximumAllowableLimits: new ScanToolResourceRequirements(
            CpuCores: 4.0,
            MemoryBytes: 2_147_483_648, // 2 GiB
            ScratchBytes: 1_073_741_824, // 1 GiB
            Timeout: TimeSpan.FromMinutes(45)
        )
    );

    private static readonly Dictionary<SecurityScanProfileType, ScanProfileDefinition> Profiles = new()
    {
        [SecurityScanProfileType.Recon] = ReconProfile,
        [SecurityScanProfileType.Standard] = StandardProfile,
        [SecurityScanProfileType.Deep] = DeepProfile
    };

    /// <summary>
    /// Resolves any compatibility alias to its canonical profile enum value.
    /// WebAssessment -> Standard, FullAssessment -> Deep.
    /// </summary>
    public static SecurityScanProfileType CanonicalizeProfile(SecurityScanProfileType profile) => profile switch
    {
        SecurityScanProfileType.WebAssessment => SecurityScanProfileType.Standard,
        SecurityScanProfileType.FullAssessment => SecurityScanProfileType.Deep,
        _ => profile
    };

    /// <summary>
    /// Returns the canonical profile definition for a given profile type.
    /// </summary>
    public static ScanProfileDefinition GetProfileDefinition(SecurityScanProfileType profile)
    {
        var canonical = CanonicalizeProfile(profile);
        return Profiles.TryGetValue(canonical, out var def) ? def : StandardProfile;
    }

    /// <summary>
    /// Returns all canonical profile definitions.
    /// </summary>
    public static IReadOnlyList<ScanProfileDefinition> GetAllProfiles() => Profiles.Values.ToList();

    /// <summary>
    /// Returns whether the output format is structured and machine-parseable for finding ingestion.
    /// </summary>
    public static bool IsOutputFormatMachineParseable(ToolOutputFormat format) => format switch
    {
        ToolOutputFormat.Json => true,
        ToolOutputFormat.JsonLines => true,
        ToolOutputFormat.Sarif => true,
        ToolOutputFormat.Xml => true,
        ToolOutputFormat.PlainText => false,
        _ => false
    };

    /// <summary>
    /// Pure deterministic compatibility evaluation between a tool capability contract and a target scan profile.
    /// Invariant: Must declare profile support, provide ALL required capabilities of the profile,
    /// support structured machine-parseable output, and strictly satisfy resource limits.
    /// </summary>
    public static ToolCompatibilityEvaluation EvaluateCompatibility(
        ScanToolCapabilityContract toolContract,
        SecurityScanProfileType profile)
    {
        if (toolContract == null) throw new ArgumentNullException(nameof(toolContract));

        var canonicalProfile = CanonicalizeProfile(profile);
        var profileDef = GetProfileDefinition(canonicalProfile);

        // 1. Profile Support Check (Canonicalized)
        var canonicalSupportedProfiles = toolContract.SupportedProfiles.Select(CanonicalizeProfile).ToHashSet();
        if (!canonicalSupportedProfiles.Contains(canonicalProfile))
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.ProfileNotSupported,
                Reason: $"Tool '{toolContract.ToolKey}' does not declare support for profile '{profileDef.CanonicalName}'."
            );
        }

        // 2. Strict Required Capabilities Check (Must satisfy ALL required capabilities of the profile)
        var toolCaps = toolContract.Capabilities.ToHashSet();
        var missingRequired = profileDef.RequiredCapabilities.Where(c => !toolCaps.Contains(c)).ToList();
        if (missingRequired.Count > 0)
        {
            var missingStr = string.Join(", ", missingRequired);
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.MissingRequiredCapability,
                Reason: $"Tool '{toolContract.ToolKey}' is missing required capability/capabilities for profile '{profileDef.CanonicalName}': {missingStr}."
            );
        }

        // 3. Machine-Parseable Output Format Check
        var hasParseableFormat = toolContract.OutputFormats.Any(IsOutputFormatMachineParseable);
        if (!hasParseableFormat)
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.MissingMachineParseableOutputFormat,
                Reason: $"Tool '{toolContract.ToolKey}' does not support any structured machine-parseable output format (e.g. JSON, JSONL, SARIF)."
            );
        }

        // 4. Strict Resource Limit Ceiling Checks (No Silent Downgrades)
        var toolLimits = toolContract.ResourceRequirements;
        var profileLimits = profileDef.MaximumAllowableLimits;

        if (toolLimits.CpuCores > profileLimits.CpuCores)
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.ExceedsCpuLimit,
                Reason: $"Tool '{toolContract.ToolKey}' requires {toolLimits.CpuCores} CPU cores, exceeding profile limit of {profileLimits.CpuCores} cores."
            );
        }

        if (toolLimits.MemoryBytes > profileLimits.MemoryBytes)
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.ExceedsMemoryLimit,
                Reason: $"Tool '{toolContract.ToolKey}' requires {toolLimits.MemoryBytes} bytes memory, exceeding profile limit of {profileLimits.MemoryBytes} bytes."
            );
        }

        if (toolLimits.ScratchBytes > profileLimits.ScratchBytes)
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.ExceedsScratchLimit,
                Reason: $"Tool '{toolContract.ToolKey}' requires {toolLimits.ScratchBytes} bytes scratch disk, exceeding profile limit of {profileLimits.ScratchBytes} bytes."
            );
        }

        if (toolLimits.Timeout > profileLimits.Timeout)
        {
            return new ToolCompatibilityEvaluation(
                toolContract.ToolKey,
                canonicalProfile,
                IsCompatible: false,
                Code: ToolProfileCompatibilityResult.ExceedsTimeoutLimit,
                Reason: $"Tool '{toolContract.ToolKey}' requires timeout {toolLimits.Timeout}, exceeding profile maximum timeout of {profileLimits.Timeout}."
            );
        }

        return new ToolCompatibilityEvaluation(
            toolContract.ToolKey,
            canonicalProfile,
            IsCompatible: true,
            Code: ToolProfileCompatibilityResult.Compatible,
            Reason: $"Tool '{toolContract.ToolKey}' is fully compatible with profile '{profileDef.CanonicalName}'."
        );
    }
}
