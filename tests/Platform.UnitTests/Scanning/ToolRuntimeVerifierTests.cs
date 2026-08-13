using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Domain.Entities;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ToolRuntimeVerifierTests
{
    private readonly ToolRuntimeVerifier _verifier = new(NullLogger<ToolRuntimeVerifier>.Instance);

    [Fact]
    public async Task ProbeToolAsync_SucceedsForValidBinaryWithMatchingKeyword()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "dotnet_test",
            Executable = "dotnet",
            Version = "unverified",
            CapabilityProbeCommand = "--help",
            CapabilityProbeExpectedKeyword = "dotnet"
        };

        var result = await _verifier.ProbeToolAsync(tool);
        result.Success.Should().BeTrue();
    }

    [Fact]
    public async Task ProbeToolAsync_FailsWhenCapabilityKeywordIsMissing()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "dotnet_test",
            Executable = "dotnet",
            Version = "unverified",
            CapabilityProbeCommand = "--help",
            CapabilityProbeExpectedKeyword = "nonexistent_subdomain_scanner_keyword_xyz"
        };

        var result = await _verifier.ProbeToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("CAPABILITY_KEYWORD_MISMATCH");
    }

    [Fact]
    public async Task ProbeToolAsync_FailsOnNonExistentExecutable()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "nonexistent",
            Executable = "nonexistent_tool_binary_xyz",
            Version = "1.0.0"
        };

        var result = await _verifier.ProbeToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("FILE_NOT_FOUND");
    }
}
