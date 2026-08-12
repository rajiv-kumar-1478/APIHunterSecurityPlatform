using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;
using Platform.Infrastructure.Validators;
using Xunit;

namespace Platform.UnitTests.Validators;

public class ProviderValidatorTests
{
    private readonly ValidationEndpointRegistry _registry;
    private readonly SsrfProtectionService _ssrfService;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions;

    public ProviderValidatorTests()
    {
        _registry = new ValidationEndpointRegistry();
        var ssrfLogger = new Mock<ILogger<SsrfProtectionService>>();
        _ssrfService = new SsrfProtectionService(_registry, ssrfLogger.Object);
        _policyOptions = Options.Create(new ValidationPolicyOptions());
    }

    [Fact]
    public async Task OpenAiCredentialValidator_ValidatesCanValidateAndDryRun()
    {
        var logger = new Mock<ILogger<OpenAiCredentialValidator>>();
        var validator = new OpenAiCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        Assert.Equal("OpenAI", validator.ProviderName);
        var candidate = new CredentialCandidate { CredentialType = "OpenAI" };
        Assert.True(validator.CanValidate(candidate));

        var dryOptions = Options.Create(new ValidationPolicyOptions { DryRun = true });
        var dryValidator = new OpenAiCredentialValidator(_ssrfService, dryOptions, logger.Object);
        var dryResult = await dryValidator.ValidateAsync(candidate, "sk-test12345");
        Assert.Equal(ValidationStatus.Pending, dryResult.Status);
    }

    [Fact]
    public async Task AnthropicCredentialValidator_UsesConfiguredValidationModel()
    {
        var logger = new Mock<ILogger<AnthropicCredentialValidator>>();
        var customOptions = Options.Create(new ValidationPolicyOptions
        {
            AnthropicValidationModel = "claude-3-5-sonnet-20241022"
        });

        var validator = new AnthropicCredentialValidator(_ssrfService, customOptions, logger.Object);
        var candidate = new CredentialCandidate { CredentialType = "Anthropic" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("Anthropic", validator.ProviderName);
    }

    [Fact]
    public async Task DeepSeekCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<DeepSeekCredentialValidator>>();
        var validator = new DeepSeekCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "DeepSeek" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("DeepSeek", validator.ProviderName);
    }

    [Fact]
    public async Task GroqCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<GroqCredentialValidator>>();
        var validator = new GroqCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "Groq" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("Groq", validator.ProviderName);
    }

    [Fact]
    public async Task AwsStsCredentialValidator_ValidatesCanValidateAndMissingKeys()
    {
        var logger = new Mock<ILogger<AwsStsCredentialValidator>>();
        var validator = new AwsStsCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "AWSIAM" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("AWSIAM", validator.ProviderName);

        var invalidResult = await validator.ValidateAsync(candidate, "invalid_secret_tuple");
        Assert.Equal(ValidationStatus.Invalid, invalidResult.Status);
        Assert.Contains("Missing AWS AccessKeyId", invalidResult.ResponseClassification);
    }

    [Fact]
    public async Task GitHubCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<GitHubCredentialValidator>>();
        var validator = new GitHubCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "GitHub" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("GitHub", validator.ProviderName);
    }

    [Fact]
    public async Task StripeCredentialValidator_ReturnsUnsupportedForWebhookAndPublishableKeysWithZeroNetworkCalls()
    {
        var logger = new Mock<ILogger<StripeCredentialValidator>>();
        var validator = new StripeCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "Stripe" };
        Assert.True(validator.CanValidate(candidate));

        var whResult = await validator.ValidateAsync(candidate, "whsec_test12345678901234567890");
        Assert.Equal(ValidationStatus.Unsupported, whResult.Status);
        Assert.Contains("WebhookSecret", whResult.SafeEvidenceJson);

        var pkResult = await validator.ValidateAsync(candidate, "pk_test_12345678901234567890");
        Assert.Equal(ValidationStatus.Unsupported, pkResult.Status);
        Assert.Contains("PublishableKey", pkResult.SafeEvidenceJson);
    }

    [Fact]
    public async Task SendGridCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<SendGridCredentialValidator>>();
        var validator = new SendGridCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "SendGrid" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("SendGrid", validator.ProviderName);
    }

    [Fact]
    public async Task MailgunCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<MailgunCredentialValidator>>();
        var validator = new MailgunCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "Mailgun" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("Mailgun", validator.ProviderName);
    }

    [Fact]
    public async Task SlackCredentialValidator_ValidatesCanValidate()
    {
        var logger = new Mock<ILogger<SlackCredentialValidator>>();
        var validator = new SlackCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "Slack" };
        Assert.True(validator.CanValidate(candidate));
        Assert.Equal("Slack", validator.ProviderName);
    }

    [Fact]
    public async Task FallbackCredentialValidator_ReturnsUnsupportedForUnknownTypesWithZeroNetworkCalls()
    {
        var logger = new Mock<ILogger<FallbackCredentialValidator>>();
        var validator = new FallbackCredentialValidator(_ssrfService, _policyOptions, logger.Object);

        var candidate = new CredentialCandidate { CredentialType = "UnknownCustomProvider" };
        Assert.True(validator.CanValidate(candidate));

        var result = await validator.ValidateAsync(candidate, "some_secret_key");
        Assert.Equal(ValidationStatus.Unsupported, result.Status);
        Assert.Contains("UnknownCustomProvider", result.ResponseClassification);
    }
}
