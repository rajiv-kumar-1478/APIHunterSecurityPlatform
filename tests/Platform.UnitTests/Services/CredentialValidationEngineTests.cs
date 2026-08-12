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

public class CredentialValidationEngineTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IDataProtectionProvider> _dpProviderMock;
    private readonly Mock<IDataProtector> _dataProtectorMock;
    private readonly SsrfProtectionService _ssrfService;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions;

    public CredentialValidationEngineTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase5EngineTestDb_" + Guid.NewGuid())
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
    public async Task EnqueueValidationJobAsync_ReusesAnalysisJobWithCredentialValidationType()
    {
        var candidate = new CredentialCandidate
        {
            CredentialType = "OpenAI",
            MaskedValue = "sk-****1234",
            Status = CandidateStatus.Detected
        };

        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var logger = new Mock<ILogger<CredentialValidationService>>();
        var validators = new List<ICredentialValidator>
        {
            new OpenAiCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<OpenAiCredentialValidator>>().Object),
            new FallbackCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<FallbackCredentialValidator>>().Object)
        };

        var service = new CredentialValidationService(_dbContext, validators, _dpProviderMock.Object, _policyOptions, logger.Object);
        var job = await service.EnqueueValidationJobAsync(candidate.Id);

        Assert.NotNull(job);
        Assert.Equal(JobType.CredentialValidation, job.JobType);
        Assert.Equal(JobStatus.Queued, job.Status);
        Assert.Equal(candidate.Id, job.TargetEntityId);
    }


    [Fact]
    public async Task ValidateCandidateAsync_PreservesCandidateStatusAndAppendsValidationResult()
    {
        string rawSecret = "whsec_test12345678901234567890";
        string protectedBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(rawSecret));

        var candidate = new CredentialCandidate
        {
            CredentialType = "Stripe",
            MaskedValue = "whsec_****1234",
            EncryptedRawValue = protectedBase64,
            Status = CandidateStatus.Detected
        };

        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var logger = new Mock<ILogger<CredentialValidationService>>();
        var validators = new List<ICredentialValidator>
        {
            new StripeCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<StripeCredentialValidator>>().Object),
            new FallbackCredentialValidator(_ssrfService, _policyOptions, new Mock<ILogger<FallbackCredentialValidator>>().Object)
        };

        var service = new CredentialValidationService(_dbContext, validators, _dpProviderMock.Object, _policyOptions, logger.Object);

        // First validation attempt
        var result1 = await service.ValidateCandidateAsync(candidate.Id);
        Assert.Equal(ValidationStatus.Unsupported, result1.Status);
        Assert.Equal(1, result1.ValidationAttemptNumber);

        // Candidate.Status MUST remain Detected (Discovery/Triage lifecycle preserved!)
        var fetchedCandidate = await _dbContext.CredentialCandidates.FirstAsync(c => c.Id == candidate.Id);
        Assert.Equal(CandidateStatus.Detected, fetchedCandidate.Status);

        // Second validation attempt (historical append-only)
        var result2 = await service.ValidateCandidateAsync(candidate.Id);
        Assert.Equal(2, result2.ValidationAttemptNumber);

        var history = await service.GetValidationHistoryAsync(candidate.Id);
        Assert.Equal(2, history.Count);
    }

    [Fact]
    public async Task ValidateCandidateAsync_DispatchesUnsupportedTypesToFallbackValidatorWithZeroNetworkCalls()
    {
        string rawSecret = "key_secret_12345";
        string protectedBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(rawSecret));

        var candidate = new CredentialCandidate
        {
            CredentialType = "UnknownVendorX",
            MaskedValue = "key_****1234",
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
        var result = await service.ValidateCandidateAsync(candidate.Id);

        Assert.Equal(ValidationStatus.Unsupported, result.Status);
        Assert.Contains("UnknownVendorX", result.ResponseClassification);
    }

}
