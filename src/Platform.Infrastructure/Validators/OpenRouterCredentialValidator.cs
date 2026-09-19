using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class OpenRouterCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "OpenRouter";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://openrouter.ai/api/v1/auth/key",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "OpenRouter key metadata verified"
    };

    public OpenRouterCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<OpenRouterCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
