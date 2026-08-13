using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Scanning;
using Platform.Domain.Entities;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ToolProvisioningServiceTests
{
    private readonly Mock<IEgressPolicyEngine> _mockEgressEngine;
    private readonly ToolProvisioningService _service;

    public ToolProvisioningServiceTests()
    {
        _mockEgressEngine = new Mock<IEgressPolicyEngine>();
        _mockEgressEngine.Setup(e => e.EvaluateAndBuildTargetAsync(It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<System.Threading.CancellationToken>()))
                         .ReturnsAsync((string url, TimeSpan? timeout, System.Threading.CancellationToken ct) =>
                             new Platform.Application.Scanning.Contracts.EgressTarget("github.com", "140.82.121.4", 443, "https", new System.Collections.Generic.HashSet<System.Net.IPAddress> { System.Net.IPAddress.Parse("140.82.121.4") }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(10), "v1.0"));

        _service = new ToolProvisioningService(NullLogger<ToolProvisioningService>.Instance, _mockEgressEngine.Object);
    }

    [Fact]
    public void Constructor_ThrowsArgumentNullException_WhenEgressEngineIsNull()
    {
        Action act = () => new ToolProvisioningService(NullLogger<ToolProvisioningService>.Instance, egressPolicyEngine: null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("egressPolicyEngine");
    }

    [Fact]
    public async Task CustomDownloader_Cannot_Bypass_EgressPolicy()
    {
        var mockEgressEngine = new Mock<IEgressPolicyEngine>();
        mockEgressEngine.Setup(e => e.EvaluateAndBuildTargetAsync(It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<System.Threading.CancellationToken>()))
                         .Throws(new InvalidOperationException("Prohibited target egress."));

        var downloaderInvoked = false;
        Func<SecurityScanTool, System.Threading.CancellationToken, Task<Stream>> customDownloader = (t, ct) =>
        {
            downloaderInvoked = true;
            return Task.FromResult<Stream>(new MemoryStream(Encoding.UTF8.GetBytes("EVIL")));
        };

        var service = new ToolProvisioningService(NullLogger<ToolProvisioningService>.Instance, mockEgressEngine.Object, artifactDownloader: customDownloader);

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
        downloaderInvoked.Should().BeFalse("Custom downloader must NEVER be invoked if egress policy evaluation fails");
    }

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
    public async Task ProvisionToolAsync_RejectsRepositoryUrlMismatch()
    {
        var tool = new SecurityScanTool
        {
            ToolKey = "subfinder",
            Version = "v2.6.6",
            ArtifactSourceType = "github-release",
            ArtifactRepository = "projectdiscovery/subfinder",
            ArtifactUrl = "https://github.com/malicious/other-repo/releases/v2.6.6/subfinder.zip",
            ArtifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            Executable = "subfinder"
        };

        var result = await _service.ProvisionToolAsync(tool);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("REPOSITORY_URL_MISMATCH");
    }

    [Fact]
    public async Task ProvisionToolAsync_RejectsProhibitedSsrfArtifactUrl()
    {
        var mockEgressEngine = new Mock<IEgressPolicyEngine>();
        mockEgressEngine.Setup(e => e.EvaluateAndBuildTargetAsync(It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<System.Threading.CancellationToken>()))
                         .Throws(new InvalidOperationException("Prohibited IMDS metadata IP target."));

        var service = new ToolProvisioningService(NullLogger<ToolProvisioningService>.Instance, mockEgressEngine.Object);

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
            _mockEgressEngine.Object,
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
            _mockEgressEngine.Object,
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
    public async Task ZIP_SiblingPrefixEscape_IsRejected()
    {
        await AssertZipEntryRejectedAsync("../apihunter_tools_sibling/evil.exe", "ZIP_SLIP_VULNERABILITY_DETECTED");
    }

    [Fact]
    public async Task ZIP_AbsoluteWindowsPath_IsRejected()
    {
        await AssertZipEntryRejectedAsync(@"C:\Windows\System32\malicious.exe", "ZIP_SLIP_VULNERABILITY_DETECTED");
    }

    [Fact]
    public async Task ZIP_AbsoluteUnixPath_IsRejected()
    {
        await AssertZipEntryRejectedAsync("/etc/passwd", "ZIP_SLIP_VULNERABILITY_DETECTED");
    }

    [Fact]
    public async Task ZIP_NestedTraversal_IsRejected()
    {
        await AssertZipEntryRejectedAsync("subdir/../../escape.exe", "ZIP_SLIP_VULNERABILITY_DETECTED");
    }

    [Fact]
    public async Task ZIP_Symlink_IsRejected()
    {
        var tempZipPath = Path.Combine(Path.GetTempPath(), $"zip_symlink_{Guid.NewGuid():N}.zip");
        try
        {
            using (var zipStream = File.Create(tempZipPath))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("symlink_target");
                // Unix symlink bit flag 0xA000 << 16
                entry.ExternalAttributes = 0xA000 << 16;
                using var entryWriter = new StreamWriter(entry.Open());
                entryWriter.Write("/etc/passwd");
            }

            var zipBytes = await File.ReadAllBytesAsync(tempZipPath);
            var expectedSha256 = Convert.ToHexStringLower(SHA256.HashData(zipBytes));

            var service = new ToolProvisioningService(
                NullLogger<ToolProvisioningService>.Instance,
                _mockEgressEngine.Object,
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
            result.ErrorCode.Should().Be("ZIP_SYMLINK_PROHIBITED");
        }
        finally
        {
            if (File.Exists(tempZipPath)) File.Delete(tempZipPath);
        }
    }

    private async Task AssertZipEntryRejectedAsync(string zipEntryPath, string expectedErrorCode)
    {
        var tempZipPath = Path.Combine(Path.GetTempPath(), $"zip_test_{Guid.NewGuid():N}.zip");
        try
        {
            using (var zipStream = File.Create(tempZipPath))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry(zipEntryPath);
                using var entryWriter = new StreamWriter(entry.Open());
                entryWriter.Write("malicious_content");
            }

            var zipBytes = await File.ReadAllBytesAsync(tempZipPath);
            var expectedSha256 = Convert.ToHexStringLower(SHA256.HashData(zipBytes));

            var service = new ToolProvisioningService(
                NullLogger<ToolProvisioningService>.Instance,
                _mockEgressEngine.Object,
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
            result.ErrorCode.Should().Be(expectedErrorCode);
        }
        finally
        {
            if (File.Exists(tempZipPath)) File.Delete(tempZipPath);
        }
    }
}
