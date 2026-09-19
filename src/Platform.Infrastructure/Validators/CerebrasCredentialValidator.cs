using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class CerebrasCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Cerebras";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.cerebras.ai/v1/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "Cerebras model catalog verified"
    };

    public CerebrasCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<CerebrasCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
