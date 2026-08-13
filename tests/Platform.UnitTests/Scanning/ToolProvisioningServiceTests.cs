using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning;
using Platform.Domain.Entities;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ToolProvisioningServiceTests
{
    private readonly ToolProvisioningService _service = new(NullLogger<ToolProvisioningService>.Instance);

    [Fact]
    public async Task ProvisionToolAsync_RejectsUntrustedSourceType()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "untrusted-http",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            Executable = "subfinder"
        };

        var result = await _service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("UNTRUSTED_ARTIFACT_SOURCE");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsUnapprovedRepository()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "malicious-user/evil-subfinder",
            ArtifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            Executable = "subfinder"
        };

        var result = await _service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("UNAPPROVED_REPOSITORY");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsMissingSha256()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactSha256 = "",
            Executable = "subfinder"
        };

        var result = await _service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("MISSING_ARTIFACT_SHA256");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsUntrustedArtifactUrlDomain()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactUrl = "https://evil-untrusted-domain.com/subfinder.zip",
            ArtifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            Executable = "subfinder"
        };

        var result = await _service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("UNTRUSTED_ARTIFACT_URL_DOMAIN");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsProhibitedSsrfArtifactUrl()
    {
        var mockEgressEngine = new Moq.Mock<IEgressPolicyEngine>();
        mockEgressEngine.Setup(e => e.EvaluateAndBuildTargetAsync(Moq.It.IsAny<string>(), Moq.It.IsAny<TimeSpan?>(), Moq.It.IsAny<System.Threading.CancellationToken>()))
                         .Throws(new InvalidOperationException("Prohibited IMDS metadata IP target."));

        var service = new ToolProvisioningService(NullLogger<ToolProvisioningService>.Instance, egressPolicyEngine: mockEgressEngine.Object);

        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactUrl = "https://github.com/projectdiscovery/subfinder/releases/v2.6.6/subfinder.zip",
            ArtifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            Executable = "subfinder"
        };

        var result = await service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("ARTIFACT_URL_PROHIBITED_SSRF");
    }

    [Fact]
    public async Task ProvisionToolAsync_Succeeds_WhenStreamSha256MatchesExpectedHash()
    {
        var artifactBytes = Encoding.UTF8.GetBytes("ACTUAL_BINARY_CONTENT_FOR_SUBFINDER");
        var expectedSha256 = Convert.ToHexStringLower(SHA256.HashData(artifactBytes));

        var service = new ToolProvisioningService(
            NullLogger<ToolProvisioningService>.Instance,
            artifactDownloader: (t, ct) => Task.FromResult<Stream>(new MemoryStream(artifactBytes)));

        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactUrl = "https://github.com/projectdiscovery/subfinder/releases/v2.6.6/subfinder.zip",
            ArtifactSha256 = expectedSha256,
            Executable = "subfinder"
        };

        var result = await service.ProvisionToolAsync(tool);

        result.Success.Should().BeTrue();
        result.InstallPath.Should().NotBeEmpty();
        File.Exists(result.InstallPath).Should().BeTrue("Downloaded executable binary must exist at install path");

        var actualFileBytes = await File.ReadAllBytesAsync(result.InstallPath);
        actualFileBytes.Should().Equal(artifactBytes, "Installed binary must match exact downloaded artifact bytes");
    }

    [Fact]
    public async Task ProvisionToolAsync_FailsAndCleansUp_WhenChecksumMismatches()
    {
        var artifactBytes = Encoding.UTF8.GetBytes("CORRUPTED_BINARY_CONTENT");
        var wrongSha256 = "1111111111222222222233333333334444444444555555555566666666667777";

        var service = new ToolProvisioningService(
            NullLogger<ToolProvisioningService>.Instance,
            artifactDownloader: (t, ct) => Task.FromResult<Stream>(new MemoryStream(artifactBytes)));

        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactUrl = "https://github.com/projectdiscovery/subfinder/releases/v2.6.6/subfinder.zip",
            ArtifactSha256 = wrongSha256,
            Executable = "subfinder"
        };

        var result = await service.ProvisionToolAsync(tool);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("CHECKSUM_MISMATCH");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsZipArchiveWithZipSlipTraversal()
    {
        var tempZipPath = Path.Combine(Path.GetTempPath(), $"zip_slip_{Guid.NewGuid():N}.zip");
        try
        {
            using (var zipStream = File.Create(tempZipPath))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("../escape.exe");
                using var entryWriter = new StreamWriter(entry.Open());
                entryWriter.Write("malicious");
            }

            var zipBytes = await File.ReadAllBytesAsync(tempZipPath);
            var expectedSha256 = Convert.ToHexStringLower(SHA256.HashData(zipBytes));

            var service = new ToolProvisioningService(
                NullLogger<ToolProvisioningService>.Instance,
                artifactDownloader: (t, ct) => Task.FromResult<Stream>(new MemoryStream(zipBytes)));

            var tool = new SecurityScanTool
            {
                ToolKey = "subfinder",
                Version = "v2.6.6",
                ArtifactSourceType = "github-release",
                ArtifactRepository = "projectdiscovery/subfinder",
                ArtifactUrl = "https://github.com/projectdiscovery/subfinder/releases/v2.6.6/subfinder.zip",
                ArtifactFormat = "zip",
                ArtifactSha256 = expectedSha256,
                Executable = "subfinder"
            };

            var result = await service.ProvisionToolAsync(tool);
            result.Success.Should().BeFalse();
            result.ErrorCode.Should().Be("ZIP_SLIP_VULNERABILITY_DETECTED");
        }
        finally
        {
            if (File.Exists(tempZipPath)) File.Delete(tempZipPath);
        }
    }
}
