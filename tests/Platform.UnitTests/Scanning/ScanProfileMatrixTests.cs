using System;
using System.Collections.Generic;
using FluentAssertions;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanProfileMatrixTests
{
    [Fact]
    public void ScanProfileMatrix_EnforcesCanonicalProfileLimits()
    {
        var recon = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.Recon);
        recon.CanonicalName.Should().Be("Recon");
        recon.MaximumAllowableLimits.CpuCores.Should().Be(1.0);
        recon.MaximumAllowableLimits.MemoryBytes.Should().Be(536_870_912); // 512 MiB
        recon.MaximumAllowableLimits.Timeout.Should().Be(TimeSpan.FromMinutes(10));
        recon.RequiredCapabilities.Should().Contain(ToolCapability.SubdomainEnumeration);
        recon.RequiredCapabilities.Should().Contain(ToolCapability.DnsResolution);
        recon.RequiredCapabilities.Should().Contain(ToolCapability.HttpProbing);

        var standard = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.Standard);
        standard.CanonicalName.Should().Be("Standard");
        standard.MaximumAllowableLimits.CpuCores.Should().Be(2.0);
        standard.MaximumAllowableLimits.MemoryBytes.Should().Be(1_073_741_824); // 1 GiB
        standard.MaximumAllowableLimits.Timeout.Should().Be(TimeSpan.FromMinutes(20));
        standard.RequiredCapabilities.Should().Contain(ToolCapability.HttpProbing);
        standard.RequiredCapabilities.Should().Contain(ToolCapability.UrlCrawling);
        standard.RequiredCapabilities.Should().Contain(ToolCapability.VulnerabilityScanning);

        var deep = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.Deep);
        deep.CanonicalName.Should().Be("Deep");
        deep.MaximumAllowableLimits.CpuCores.Should().Be(4.0);
        deep.MaximumAllowableLimits.MemoryBytes.Should().Be(2_147_483_648); // 2 GiB
        deep.MaximumAllowableLimits.Timeout.Should().Be(TimeSpan.FromMinutes(45));
        deep.RequiredCapabilities.Should().Contain(ToolCapability.Fuzzing);
        deep.RequiredCapabilities.Should().Contain(ToolCapability.AiAssistedHunting);
    }

    [Fact]
    public void ScanProfileMatrix_AliasesMapToCanonicalDefinitions()
    {
        var webAssessment = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.WebAssessment);
        var standard = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.Standard);
        webAssessment.Should().BeEquivalentTo(standard);

        var fullAssessment = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.FullAssessment);
        var deep = ScanProfileMatrix.GetProfileDefinition(SecurityScanProfileType.Deep);
        fullAssessment.Should().BeEquivalentTo(deep);
    }

    [Fact]
    public void EvaluateCompatibility_CompatibleTool_ReturnsPass()
    {
        var subfinder = new ScanToolCapabilityContract(
            ToolKey: "subfinder",
            DisplayName: "Subfinder Passive Subdomain Tool",
            Version: "v2.6.6",
            Capabilities: new[] { ToolCapability.SubdomainEnumeration },
            SupportedProfiles: new[] { SecurityScanProfileType.Recon, SecurityScanProfileType.Deep },
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.Json, ToolOutputFormat.PlainText },
            ResourceRequirements: new ScanToolResourceRequirements(
                CpuCores: 0.5,
                MemoryBytes: 268_435_456, // 256 MiB
                ScratchBytes: 67_108_864, // 64 MiB
                Timeout: TimeSpan.FromMinutes(5)
            ),
            ContractVersion: "1.0"
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(subfinder, SecurityScanProfileType.Recon);
        eval.IsCompatible.Should().BeTrue();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.Compatible);
    }

    [Fact]
    public void EvaluateCompatibility_UnsupportedProfile_FailsClosed()
    {
        var subfinder = new ScanToolCapabilityContract(
            ToolKey: "subfinder",
            DisplayName: "Subfinder Passive Subdomain Tool",
            Version: "v2.6.6",
            Capabilities: new[] { ToolCapability.SubdomainEnumeration },
            SupportedProfiles: new[] { SecurityScanProfileType.Recon }, // Only Recon
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.Json },
            ResourceRequirements: new ScanToolResourceRequirements(0.5, 268_435_456, 67_108_864, TimeSpan.FromMinutes(5))
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(subfinder, SecurityScanProfileType.Standard);
        eval.IsCompatible.Should().BeFalse();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.ProfileNotSupported);
        eval.Reason.Should().Contain("does not declare support for profile 'Standard'");
    }

    [Fact]
    public void EvaluateCompatibility_PlainTextOnlyOutput_FailsClosedForFindingIngestion()
    {
        var legacyTool = new ScanToolCapabilityContract(
            ToolKey: "legacy_probe",
            DisplayName: "Legacy Terminal Prober",
            Version: "v1.0.0",
            Capabilities: new[] { ToolCapability.HttpProbing },
            SupportedProfiles: new[] { SecurityScanProfileType.Recon },
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.PlainText }, // Only PlainText
            ResourceRequirements: new ScanToolResourceRequirements(0.5, 268_435_456, 67_108_864, TimeSpan.FromMinutes(5))
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(legacyTool, SecurityScanProfileType.Recon);
        eval.IsCompatible.Should().BeFalse();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.MissingMachineParseableOutputFormat);
        eval.Reason.Should().Contain("does not support any structured machine-parseable output format");
    }

    [Fact]
    public void EvaluateCompatibility_ExceedsCpuLimit_FailsClosedWithoutSilentDowngrade()
    {
        var heavyFuzzer = new ScanToolCapabilityContract(
            ToolKey: "heavy_fuzzer",
            DisplayName: "Heavy CPU Fuzzer",
            Version: "v1.0.0",
            Capabilities: new[] { ToolCapability.SubdomainEnumeration },
            SupportedProfiles: new[] { SecurityScanProfileType.Recon },
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.Json },
            ResourceRequirements: new ScanToolResourceRequirements(
                CpuCores: 2.0, // Exceeds Recon limit of 1.0
                MemoryBytes: 268_435_456,
                ScratchBytes: 67_108_864,
                Timeout: TimeSpan.FromMinutes(5)
            )
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(heavyFuzzer, SecurityScanProfileType.Recon);
        eval.IsCompatible.Should().BeFalse();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.ExceedsCpuLimit);
        eval.Reason.Should().Contain("requires 2 CPU cores, exceeding profile limit of 1 cores");
    }

    [Fact]
    public void EvaluateCompatibility_ExceedsMemoryLimit_FailsClosed()
    {
        var ramHungryScanner = new ScanToolCapabilityContract(
            ToolKey: "ram_scanner",
            DisplayName: "RAM Intensive Scanner",
            Version: "v1.0.0",
            Capabilities: new[] { ToolCapability.SubdomainEnumeration },
            SupportedProfiles: new[] { SecurityScanProfileType.Recon },
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.Json },
            ResourceRequirements: new ScanToolResourceRequirements(
                CpuCores: 0.5,
                MemoryBytes: 1_073_741_824, // 1 GiB exceeds Recon limit of 512 MiB
                ScratchBytes: 67_108_864,
                Timeout: TimeSpan.FromMinutes(5)
            )
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(ramHungryScanner, SecurityScanProfileType.Recon);
        eval.IsCompatible.Should().BeFalse();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.ExceedsMemoryLimit);
    }

    [Fact]
    public void EvaluateCompatibility_ExceedsTimeoutLimit_FailsClosed()
    {
        var slowCrawler = new ScanToolCapabilityContract(
            ToolKey: "slow_crawler",
            DisplayName: "Slow Exhaustive Crawler",
            Version: "v1.0.0",
            Capabilities: new[] { ToolCapability.HttpProbing },
            SupportedProfiles: new[] { SecurityScanProfileType.Standard },
            RequiredPermissions: new[] { "scans.execute" },
            OutputFormats: new[] { ToolOutputFormat.Json },
            ResourceRequirements: new ScanToolResourceRequirements(
                CpuCores: 1.0,
                MemoryBytes: 536_870_912,
                ScratchBytes: 67_108_864,
                Timeout: TimeSpan.FromMinutes(30) // Exceeds Standard limit of 20 min
            )
        );

        var eval = ScanProfileMatrix.EvaluateCompatibility(slowCrawler, SecurityScanProfileType.Standard);
        eval.IsCompatible.Should().BeFalse();
        eval.Code.Should().Be(ToolProfileCompatibilityResult.ExceedsTimeoutLimit);
    }
}
