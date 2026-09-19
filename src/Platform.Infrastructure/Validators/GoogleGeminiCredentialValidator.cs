using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class GoogleGeminiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "GoogleGemini";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://generativelanguage.googleapis.com/v1beta/models",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.CustomHeader,
        AuthHeaderName = "x-goog-api-key",
        SuccessJsonProperty = "models",
        SuccessLabel = "Google Gemini models catalog verified"
    };

    public GoogleGeminiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<GoogleGeminiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
