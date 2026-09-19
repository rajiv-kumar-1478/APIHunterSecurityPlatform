using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class CohereCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Cohere";

    /// <remarks>
    /// Cohere exposes a dedicated key-check endpoint that answers HTTP 200 with
    /// <c>"valid": false</c> for a rejected key, so the executor's false-flag rule applies.
    /// </remarks>
    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.cohere.com/v1/check-api-key",
        Method = HttpMethod.Post,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        JsonBody = "{}",
        SuccessJsonProperty = "valid",
        SuccessLabel = "Cohere key check verified"
    };

    public CohereCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<CohereCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
