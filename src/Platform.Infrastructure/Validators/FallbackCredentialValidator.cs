using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public class FallbackCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "Fallback";

    public FallbackCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<FallbackCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    public override bool CanValidate(CredentialCandidate candidate)
    {
        // Fallback validator catches any unsupported credential type
        return true;
    }

    protected override Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        stopwatch.Stop();
        string candidateType = candidate.CredentialType ?? "Unknown";

        var result = new ValidationResultDto(
            ValidationStatus.Unsupported,
            ValidationConfidence.Strong,
            $"Credential type '{candidateType}' is unsupported for live network validation",
            "{}",
            stopwatch.ElapsedMilliseconds);

        return Task.FromResult(result);
    }
}
