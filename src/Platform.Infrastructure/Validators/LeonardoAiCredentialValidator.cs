using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class LeonardoAiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "LeonardoAI";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://cloud.leonardo.ai/api/rest/v1/me",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "user_details",
        SuccessLabel = "Leonardo AI account verified"
    };

    public LeonardoAiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<LeonardoAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
