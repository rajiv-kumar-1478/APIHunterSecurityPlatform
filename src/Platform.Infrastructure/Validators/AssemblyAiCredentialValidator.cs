using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class AssemblyAiCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "AssemblyAI";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.assemblyai.com/v2/transcript",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.RawAuthorization,
        SuccessLabel = "AssemblyAI service access verified"
    };

    public AssemblyAiCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<AssemblyAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
