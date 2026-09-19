using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public sealed class TavilyCredentialValidator : DeclarativeHttpCredentialValidator
{
    public override string ProviderName => "Tavily";

    /// <remarks>
    /// Tavily's account endpoint returns an authenticated 200 without a stable top-level
    /// verification field, so HTTP 200 alone is the success signal.
    /// </remarks>
    public override ProviderValidationDescriptor Descriptor { get; } = new()
    {
        RequestUri = "https://api.tavily.com/user",
        Method = HttpMethod.Get,
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessLabel = "Tavily account access verified"
    };

    public TavilyCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<TavilyCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }
}
