using System.Formats.Tar;
using System.IO.Compression;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Infrastructure.Services;

namespace Platform.UnitTests.Services;

internal static class AiInvestigationEngineTestFactory
{
    public static AiInvestigationEngine Create(
        IPlatformDbContext dbContext,
        IAiModelRouter modelRouter,
        ILogger<AiInvestigationEngine> logger,
        AiInvestigationEngineOptions? options = null)
    {
        var provider = new Mock<IRepositoryProvider>();
        provider
            .Setup(p => p.DownloadArchiveAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Returns(() => Task.FromResult(CreateEmptyArchive()));

        var contentReader = new RepositoryContentReader(
            new Mock<IObjectStore>().Object,
            provider.Object,
            NullLogger<RepositoryContentReader>.Instance);

        return new AiInvestigationEngine(
            dbContext,
            modelRouter,
            contentReader,
            new EphemeralDataProtectionProvider(),
            Options.Create(new DetectionOptions()),
            logger,
            options);
    }

    private static Stream CreateEmptyArchive()
    {
        var buffer = new MemoryStream();
        using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(new byte[1024]);
        }

        buffer.Position = 0;
        return buffer;
    }
}
