using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class KlingAiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "KlingAI";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.klingai.com/v1/user/info",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessLabel = "Kling AI key verified"
    };

    public KlingAiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<KlingAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
