using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Security;
using Platform.Infrastructure.Validators;
using Xunit;

namespace Platform.UnitTests.Services;

public class Phase5FullIntegrationAndSecretLeakTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IDataProtectionProvider> _dpProviderMock;
    private readonly Mock<IDataProtector> _dataProtectorMock;
    private readonly SsrfProtectionService _ssrfService;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions;

    public Phase5FullIntegrationAndSecretLeakTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase5SecretLeakTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _dataProtectorMock = new Mock<IDataProtector>();
        _dataProtectorMock.Setup(dp => dp.Unprotect(It.IsAny<byte[]>()))
            .Returns((byte[] input) => input);

        _dpProviderMock = new Mock<IDataProtectionProvider>();
        _dpProviderMock.Setup(dp => dp.CreateProtector(It.IsAny<string>()))
            .Returns(_dataProtectorMock.Object);

        var registry = new ValidationEndpointRegistry();
        var ssrfLogger = new Mock<ILogger<SsrfProtectionService>>();
        _ssrfService = new SsrfProtectionService(registry, ssrfLogger.Object);
        _policyOptions = Options.Create(new ValidationPolicyOptions());
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task SecretCandidate_NeverExposesRawSecretsInMaskedValueOrValidationResults()
    {
        string rawSecret = "sk-proj-12345678901234567890abcdefghijklmnopqrstuvwxyz";
        string protectedBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(rawSecret));

        var candidate = new CredentialCandidate
        {
            CredentialType = "OpenAI",
            MaskedValue = "sk-proj-****vwxyz",
            EncryptedRawValue = protectedBase64,
            Status = CandidateStatus.Detected
        };

        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var logger = new Mock<ILogger<CredentialValidationService>>();
        var validators = new List<ICredentialValidator>
        {
            new FallbackCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<FallbackCredentialValidator>>().Object)
        };

        var service = new CredentialValidationService(_dbContext, validators, _dpProviderMock.Object, _policyOptions, logger.Object);
        var valResult = await service.ValidateCandidateAsync(candidate.Id);

        // 1. Assert ValidationResult contains NO raw secrets
        Assert.DoesNotContain(rawSecret, valResult.SafeEvidenceJson);
        Assert.DoesNotContain(rawSecret, valResult.ResponseClassification);

        // 2. Assert Candidate.MaskedValue remains strictly masked
        Assert.Equal("sk-proj-****vwxyz", candidate.MaskedValue);
        Assert.DoesNotContain(rawSecret, candidate.MaskedValue);

        // 3. Assert AuditEvents logged contain zero raw credentials
        var audit = await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.ResourceId == candidate.Id.ToString());
        Assert.NotNull(audit);
        Assert.DoesNotContain(rawSecret, audit.Metadata);
    }

    [Fact]
    public async Task ValidationStatusTransitions_DistinguishRateLimitedAndUnsupportedFromInvalid()
    {
        // Assert Enum Distinctions
        Assert.NotEqual(ValidationStatus.Invalid, ValidationStatus.RateLimited);
        Assert.NotEqual(ValidationStatus.Invalid, ValidationStatus.Unsupported);
        Assert.NotEqual(ValidationStatus.Invalid, ValidationStatus.Unavailable);
        Assert.NotEqual(ValidationStatus.Invalid, ValidationStatus.BlockedByPolicy);

        // Test Unsupported Validation Output
        var candidate = new CredentialCandidate
        {
            CredentialType = "CustomProprietaryToken",
            MaskedValue = "cust_****9999",
            EncryptedRawValue = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("raw_cust_secret")),
            Status = CandidateStatus.Detected
        };

        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var logger = new Mock<ILogger<CredentialValidationService>>();
        var validators = new List<ICredentialValidator>
        {
            new FallbackCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<FallbackCredentialValidator>>().Object)
        };

        var service = new CredentialValidationService(_dbContext, validators, _dpProviderMock.Object, _policyOptions, logger.Object);
        var valResult = await service.ValidateCandidateAsync(candidate.Id);

        Assert.Equal(ValidationStatus.Unsupported, valResult.Status);
        Assert.Equal(ValidationConfidence.Strong, valResult.Confidence);
    }

}
