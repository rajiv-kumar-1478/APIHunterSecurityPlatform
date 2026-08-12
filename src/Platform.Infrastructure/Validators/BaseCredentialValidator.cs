using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public abstract class BaseCredentialValidator : ICredentialValidator
{
    protected readonly SsrfProtectionService _ssrfProtectionService;
    protected readonly IOptions<ValidationPolicyOptions> _policyOptions;
    protected readonly ILogger _logger;

    public abstract string ProviderName { get; }
    public virtual string ValidatorVersion => "1.0.0";

    protected BaseCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger logger)
    {
        _ssrfProtectionService = ssrfProtectionService ?? throw new ArgumentNullException(nameof(ssrfProtectionService));
        _policyOptions = policyOptions ?? throw new ArgumentNullException(nameof(policyOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public virtual bool CanValidate(CredentialCandidate candidate)
    {
        if (candidate == null) return false;
        return string.Equals(candidate.CredentialType, ProviderName, StringComparison.OrdinalIgnoreCase);
    }

    public async Task<ValidationResultDto> ValidateAsync(CredentialCandidate candidate, string decryptedSecret, CancellationToken ct = default)
    {
        if (candidate == null)
        {
            return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, "Null candidate provided", "{}", 0);
        }

        var policy = _policyOptions.Value;
        if (!policy.GlobalEnabled)
        {
            return new ValidationResultDto(ValidationStatus.BlockedByPolicy, ValidationConfidence.Indeterminate, "Validation globally disabled by policy", "{}", 0);
        }

        if (policy.DryRun)
        {
            return new ValidationResultDto(ValidationStatus.Pending, ValidationConfidence.Indeterminate, "Validation dry run mode enabled", "{}", 0);
        }

        if (string.IsNullOrWhiteSpace(decryptedSecret))
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Strong, "Empty or null secret", "{}", 0);
        }


        var stopwatch = Stopwatch.StartNew();
        try
        {
            return await ExecuteValidationAsync(candidate, decryptedSecret, stopwatch, ct);
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new ValidationResultDto(ValidationStatus.Unavailable, ValidationConfidence.Indeterminate, "Validation operation timed out or cancelled", "{}", stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Unexpected validation error for provider '{Provider}'. Secret is isolated.", ProviderName);
            return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"Validator exception: {ex.Message}", "{}", stopwatch.ElapsedMilliseconds);
        }
    }

    protected abstract Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct);

    protected HttpClient CreateSsrfClient()
    {
        var handler = _ssrfProtectionService.CreatePinnedSsrfHandler(ProviderName);
        return new HttpClient(handler, disposeHandler: true);
    }
}
