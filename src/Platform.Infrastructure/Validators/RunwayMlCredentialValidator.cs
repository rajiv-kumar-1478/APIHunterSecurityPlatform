using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class RunwayMlCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "RunwayML";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.runwayml.com/v1/user",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessLabel = "Runway ML key verified"
    };

    public RunwayMlCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<RunwayMlCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
