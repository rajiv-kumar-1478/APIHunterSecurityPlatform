using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class MistralCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Mistral";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.mistral.ai/v1/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "Mistral models catalog verified"
    };

    public MistralCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<MistralCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
