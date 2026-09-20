using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Security;
using Platform.Infrastructure.Validators;
using Xunit;

namespace Platform.UnitTests.Validators;

public class AzureOpenAiCredentialValidatorTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly ValidationEndpointRegistry _registry;
    private readonly SsrfProtectionService _ssrfService;
    private readonly AzureOpenAiCredentialValidator _validator;
    private readonly Guid _tenantId = Guid.NewGuid();

    public AzureOpenAiCredentialValidatorTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AzureOpenAiValDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _registry = new ValidationEndpointRegistry();
        _ssrfService = new SsrfProtectionService(
            _registry,
            NullLogger<SsrfProtectionService>.Instance);

        var policyOptions = Options.Create(new ValidationPolicyOptions
        {
            GlobalEnabled = true,
            DryRun = false
        });

        _validator = new AzureOpenAiCredentialValidator(
            _dbContext,
            _ssrfService,
            policyOptions,
            NullLogger<AzureOpenAiCredentialValidator>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Theory]
    [InlineData("AzureOpenAI", true)]
    [InlineData("Azure_OpenAI", true)]
    [InlineData("azureopenai", true)]
    [InlineData("OpenAI", false)]
    [InlineData("Anthropic", false)]
    public void CanValidate_MatchesOnlyAzureOpenAiVariants(string credentialType, bool expected)
    {
        var candidate = new CredentialCandidate
        {
            CredentialType = credentialType,
            TenantId = _tenantId
        };

        _validator.CanValidate(candidate).Should().Be(expected);
    }

    [Fact]
    public async Task ValidateAsync_UnconfiguredTenant_ReturnsUnsupported()
    {
        // Arrange
        var candidate = new CredentialCandidate
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            CredentialType = "AzureOpenAI"
        };

        // Act
        var result = await _validator.ValidateAsync(candidate, "0123456789abcdef0123456789abcdef", CancellationToken.None);

        // Assert
        result.Status.Should().Be(ValidationStatus.Unsupported);
        result.Message.Should().Contain("not configured for this tenant");
    }

    [Fact]
    public async Task ValidateAsync_DisabledSetting_ReturnsUnsupported()
    {
        // Arrange
        _dbContext.TenantProviderSettings.Add(new TenantProviderSetting
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            ProviderName = "AzureOpenAI",
            ResourceEndpointUrl = "https://my-resource.openai.azure.com",
            IsEnabled = false
        });
        await _dbContext.SaveChangesAsync();

        var candidate = new CredentialCandidate
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            CredentialType = "AzureOpenAI"
        };

        // Act
        var result = await _validator.ValidateAsync(candidate, "0123456789abcdef0123456789abcdef", CancellationToken.None);

        // Assert
        result.Status.Should().Be(ValidationStatus.Unsupported);
    }

    [Theory]
    [InlineData("https://evil.attacker.com")]
    [InlineData("https://my-resource.openai.azure.org")]
    [InlineData("https://169.254.169.254")]
    [InlineData("https://google.com")]
    public async Task ValidateAsync_UnauthorizedDomain_ReturnsBlockedByPolicy(string maliciousUrl)
    {
        // Arrange
        _dbContext.TenantProviderSettings.Add(new TenantProviderSetting
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            ProviderName = "AzureOpenAI",
            ResourceEndpointUrl = maliciousUrl,
            IsEnabled = true
        });
        await _dbContext.SaveChangesAsync();

        var candidate = new CredentialCandidate
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            CredentialType = "AzureOpenAI"
        };

        // Act
        var result = await _validator.ValidateAsync(candidate, "0123456789abcdef0123456789abcdef", CancellationToken.None);

        // Assert
        result.Status.Should().Be(ValidationStatus.BlockedByPolicy);
        result.Message.Should().Contain("not an authorized *.openai.azure.com domain");
    }

    [Fact]
    public async Task ValidateAsync_HttpScheme_ReturnsBlockedByPolicy()
    {
        // Arrange
        _dbContext.TenantProviderSettings.Add(new TenantProviderSetting
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            ProviderName = "AzureOpenAI",
            ResourceEndpointUrl = "http://my-resource.openai.azure.com",
            IsEnabled = true
        });
        await _dbContext.SaveChangesAsync();

        var candidate = new CredentialCandidate
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            CredentialType = "AzureOpenAI"
        };

        // Act
        var result = await _validator.ValidateAsync(candidate, "0123456789abcdef0123456789abcdef", CancellationToken.None);

        // Assert
        result.Status.Should().Be(ValidationStatus.BlockedByPolicy);
        result.Message.Should().Contain("must be a valid absolute HTTPS URL");
    }

    [Fact]
    public async Task ValidateAsync_EmptySecret_ReturnsInvalid()
    {
        // Arrange
        var candidate = new CredentialCandidate
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            CredentialType = "AzureOpenAI"
        };

        // Act
        var result = await _validator.ValidateAsync(candidate, "   ", CancellationToken.None);

        // Assert
        result.Status.Should().Be(ValidationStatus.Invalid);
    }
}
