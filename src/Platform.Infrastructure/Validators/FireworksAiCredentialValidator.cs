using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class FireworksAiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "FireworksAI";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.fireworks.ai/inference/v1/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "Fireworks AI model catalog verified"
    };

    public FireworksAiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<FireworksAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
