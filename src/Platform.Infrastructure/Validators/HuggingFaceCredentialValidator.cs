using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class HuggingFaceCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "HuggingFace";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://huggingface.co/api/whoami-v2",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "name",
        SuccessLabel = "HuggingFace token identity verified"
    };

    public HuggingFaceCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<HuggingFaceCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
