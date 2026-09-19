using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class RunPodCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "RunPod";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.runpod.io/graphql",
        Method = HttpMethod.Post,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        JsonBody = "{\"query\":\"query { myself { id } }\"}",
        SuccessJsonProperty = "data",
        SuccessLabel = "RunPod account verified"
    };

    public RunPodCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<RunPodCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
