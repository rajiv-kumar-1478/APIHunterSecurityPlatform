using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class PerplexityCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Perplexity";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.perplexity.ai/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "Perplexity model catalog verified"
    };

    public PerplexityCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<PerplexityCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
