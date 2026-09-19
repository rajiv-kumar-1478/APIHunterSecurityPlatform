using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class FalAiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "FalAi";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://rest.alpha.fal.ai/tokens",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.KeyAuthorization,
        SuccessLabel = "Fal.ai token verified"
    };

    public FalAiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<FalAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
