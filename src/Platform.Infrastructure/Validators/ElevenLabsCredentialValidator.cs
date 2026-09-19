using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class ElevenLabsCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "ElevenLabs";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.elevenlabs.io/v1/user",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.CustomHeader,
        AuthHeaderName = "xi-api-key",
        SuccessJsonProperty = "subscription",
        SuccessLabel = "ElevenLabs user subscription verified"
    };

    public ElevenLabsCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<ElevenLabsCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
