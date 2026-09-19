using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class Ai21CredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "AI21";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.ai21.com/v1/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "data",
        SuccessLabel = "AI21 Labs models catalog verified"
    };

    public Ai21CredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<Ai21CredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
