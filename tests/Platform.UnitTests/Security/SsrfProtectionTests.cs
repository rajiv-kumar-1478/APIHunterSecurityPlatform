using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Security;
using Xunit;

namespace Platform.UnitTests.Security;

public class SsrfProtectionTests
{
    private readonly SsrfProtectionService _ssrfService;
    private readonly ValidationEndpointRegistry _registry;
    private readonly Mock<ILogger<SsrfProtectionService>> _loggerMock;

    public SsrfProtectionTests()
    {
        _registry = new ValidationEndpointRegistry();
        _loggerMock = new Mock<ILogger<SsrfProtectionService>>();
        _ssrfService = new SsrfProtectionService(_registry, _loggerMock.Object);
    }

    [Fact]
    public void CandidateSuppliedUrlOrHostname_Rejected_EndpointRegistryIsSoleDestination()
    {
        // Provider "OpenAI" resolves to fixed server endpoint "https://api.openai.com"
        var uri = _registry.GetAllowlistedEndpoint("OpenAI");
        Assert.Equal("https://api.openai.com/", uri.ToString());

        // Attempting to ask registry for arbitrary evil candidate host throws exception
        Assert.Throws<InvalidOperationException>(() => _registry.GetAllowlistedEndpoint("EvilProvider"));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.53", true)]
    [InlineData("::1", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.1.100", true)]
    [InlineData("169.254.169.254", true)] // AWS / GCP Cloud Metadata
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)] // CGNAT
    [InlineData("224.0.0.1", true)] // Multicast
    [InlineData("240.0.0.1", true)] // Reserved
    [InlineData("8.8.8.8", false)] // Public Google DNS (allowed)
    [InlineData("1.1.1.1", false)] // Public Cloudflare DNS (allowed)
    public void IsBlockedIp_ValidatesIpv4AndIpv6Ranges(string ipStr, bool expectedBlocked)
    {
        var ip = IPAddress.Parse(ipStr);
        bool isBlocked = SsrfProtectionService.IsBlockedIp(ip, out string reason);
        Assert.Equal(expectedBlocked, isBlocked);
        if (expectedBlocked)
        {
            Assert.NotEmpty(reason);
        }
    }

    [Fact]
    public void IsBlockedIp_BlocksIPv6UniqueLocalAndLinkLocal()
    {
        var ulaIp = IPAddress.Parse("fc00::1");
        var linkLocalIp = IPAddress.Parse("fe80::1");

        Assert.True(SsrfProtectionService.IsBlockedIp(ulaIp, out string ulaReason));
        Assert.Contains("Unique-Local", ulaReason);

        Assert.True(SsrfProtectionService.IsBlockedIp(linkLocalIp, out string llReason));
        Assert.Contains("Link-Local", llReason);
    }

    [Fact]
    public void IsBlockedIp_BlocksIPv4MappedIPv6PrivateAddresses()
    {
        var mappedLoopback = IPAddress.Parse("::ffff:127.0.0.1");
        var mappedPrivate = IPAddress.Parse("::ffff:10.0.0.1");

        Assert.True(SsrfProtectionService.IsBlockedIp(mappedLoopback, out string reason1));
        Assert.Contains("Loopback", reason1);

        Assert.True(SsrfProtectionService.IsBlockedIp(mappedPrivate, out string reason2));
        Assert.Contains("10.0.0.0/8", reason2);
    }

    [Fact]
    public void CreatePinnedSsrfHandler_DisablesAutoRedirectAndPinsConnection()
    {
        var handler = _ssrfService.CreatePinnedSsrfHandler("OpenAI");
        Assert.False(handler.AllowAutoRedirect);
        Assert.NotNull(handler.ConnectCallback);
    }

    [Fact]
    public async Task CandidateStatus_RemainsUntouchedByValidationResult()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase5StatusTestDb_" + Guid.NewGuid())
            .Options;

        using var dbContext = new PlatformDbContext(options);

        var candidate = new CredentialCandidate
        {
            CredentialType = "OpenAI",
            MaskedValue = "sk-live-****1234",
            Status = CandidateStatus.Detected
        };

        dbContext.CredentialCandidates.Add(candidate);
        await dbContext.SaveChangesAsync();

        var result = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            ProviderName = "OpenAI",
            Status = ValidationStatus.Valid,
            Confidence = ValidationConfidence.Confirmed,
            ResponseClassification = "HTTP 200 OK - Models Listed",
            SafeEvidenceJson = "{\"modelsCount\":15}"
        };

        dbContext.CredentialValidationResults.Add(result);
        await dbContext.SaveChangesAsync();

        var fetchedCandidate = await dbContext.CredentialCandidates.FirstAsync(c => c.Id == candidate.Id);
        // CandidateStatus remains Detected (NOT overwritten by ValidationStatus.Valid!)
        Assert.Equal(CandidateStatus.Detected, fetchedCandidate.Status);

        var fetchedResult = await dbContext.CredentialValidationResults.FirstAsync(r => r.Id == result.Id);
        Assert.Equal(ValidationStatus.Valid, fetchedResult.Status);
    }
}
