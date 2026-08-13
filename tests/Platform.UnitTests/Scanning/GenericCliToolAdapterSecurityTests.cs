using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class GenericCliToolAdapterSecurityTests
{
    [Fact]
    public void Test1_ValidateScratchDirectoryPath_Rejects_PathTraversal()
    {
        var invalidPath = Path.Combine(Path.GetTempPath(), "scans", "..", "..", "Windows", "System32");

        Action act = () => GenericCliToolAdapter.ValidateScratchDirectoryPath(invalidPath);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*Path traversal attempt detected*");
    }

    [Fact]
    public void Test2_ValidateScratchDirectoryPath_Rejects_DisallowedDirectory()
    {
        var disallowedPath = "C:\\RandomUnauthorizedFolder\\scans";

        Action act = () => GenericCliToolAdapter.ValidateScratchDirectoryPath(disallowedPath);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*Scratch directory*escapes allowed temp root*");
    }

    [Fact]
    public void Test3_SanitizeOutput_MasksRawSecrets()
    {
        var secretDict = new Dictionary<string, string>
        {
            ["GROQ_API_KEY"] = "gsk_super_secret_groq_api_key_12345"
        };
        using var lease = new ProviderSecretLease("bughunter", secretDict, TimeSpan.FromMinutes(5));

        var rawOutput = "Tool log: authenticating using gsk_super_secret_groq_api_key_12345 to Groq API endpoint.";
        var sanitized = GenericCliToolAdapter.SanitizeOutput(rawOutput, lease);

        sanitized.Should().NotContain("gsk_super_secret_groq_api_key_12345");
        sanitized.Should().Contain("***MASKED_SECRET***");
    }

    [Fact]
    public async Task Test4_ExecuteAsync_Handles_MissingBinary()
    {
        var adapter = new GenericCliToolAdapter("non_existent_binary_xyz_123", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "scans", Guid.NewGuid().ToString("N"));

        var request = new ToolExecutionRequest(
            ToolKey: "non_existent_binary_xyz_123",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(5)
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, default);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("BINARY_NOT_FOUND");
    }

    [Fact]
    public async Task Test5_ExecuteAsync_Handles_Timeout()
    {
        var adapter = new GenericCliToolAdapter("powershell.exe", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "scans", Guid.NewGuid().ToString("N"));

        var request = new ToolExecutionRequest(
            ToolKey: "powershell.exe",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string> { ["Command"] = "Start-Sleep -Seconds 10" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMilliseconds(200) // Trigger rapid timeout
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, default);

        result.Status.Should().Be(ToolExecutionStatus.TimedOut);
        result.ErrorCode.Should().Be("TIMED_OUT");
    }

    [Fact]
    public async Task Test6_ExecuteAsync_Handles_Cancellation()
    {
        var adapter = new GenericCliToolAdapter("powershell.exe", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "scans", Guid.NewGuid().ToString("N"));

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(50);

        var request = new ToolExecutionRequest(
            ToolKey: "powershell.exe",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string> { ["Command"] = "Start-Sleep -Seconds 10" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10)
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, cts.Token);

        result.Status.Should().Be(ToolExecutionStatus.TimedOut);
        result.ErrorCode.Should().Be("CANCELLED");
    }

    [Fact]
    public async Task Test7_ToolReplacement_SwapsToolDefinition_WithoutChangingOrchestration()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        using var db = new PlatformDbContext(options);

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        // Tool A: Original Subdomain Finder
        await registry.RegisterToolAsync("subfinder", "Subfinder Original", "v2.14.0", true, new[] { ToolCapability.SubdomainEnumeration });

        var toolsForReconBefore = await registry.GetToolsForCapabilitiesAsync(new[] { ToolCapability.SubdomainEnumeration });
        toolsForReconBefore.Should().ContainSingle(t => t.ToolKey == "subfinder");

        // Tool B: Swapped / Added New Tool (Amass) for same capability
        await registry.RegisterToolAsync("amass", "Amass Replacement Scanner", "v4.0.0", true, new[] { ToolCapability.SubdomainEnumeration });

        var toolsForReconAfter = await registry.GetToolsForCapabilitiesAsync(new[] { ToolCapability.SubdomainEnumeration });
        toolsForReconAfter.Should().HaveCount(2);
        toolsForReconAfter.Should().Contain(t => t.ToolKey == "amass");

        // Verification: The capability manifest resolves tool dynamically without any orchestration service code change!
        var manifest = await registry.GetCapabilityManifestAsync();
        manifest.Should().Contain(c => c.CapabilityKey == "SubdomainEnumeration" && c.AvailableTools.Contains("amass"));
    }
}
