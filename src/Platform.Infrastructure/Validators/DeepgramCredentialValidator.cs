using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class DeepgramCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Deepgram";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.deepgram.com/v1/projects",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.TokenAuthorization,
        SuccessJsonProperty = "projects",
        SuccessLabel = "Deepgram projects verified"
    };

    public DeepgramCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<DeepgramCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
