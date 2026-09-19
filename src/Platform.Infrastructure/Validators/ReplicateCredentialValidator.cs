using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class ReplicateCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Replicate";

    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.replicate.com/v1/account",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = "type",
        SuccessLabel = "Replicate account identity verified"
    };

    public ReplicateCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<ReplicateCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
