using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

/// <summary>
/// Base class for providers whose credential validation is a single authenticated HTTPS
/// request with conventional status semantics.
///
/// Subclasses declare only <see cref="BaseCredentialValidator.ProviderName"/> and
/// <see cref="Descriptor"/>. All request construction, status mapping, and evidence
/// sanitization is performed once by <see cref="ProviderValidationExecutor"/>.
///
/// The 10 originally locked validators intentionally keep their bespoke implementations;
/// this base is for providers added afterwards.
/// </summary>
public abstract class DeclarativeHttpCredentialValidator : BaseCredentialValidator
{
    protected DeclarativeHttpCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    /// <summary>
    /// Server-controlled request definition for this provider. Exposed so that tests and
    /// future capability endpoints can inspect it; it contains no secret material.
    /// </summary>
    public abstract ProviderValidationDescriptor Descriptor { get; }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(
        CredentialCandidate candidate,
        string decryptedSecret,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        return await ProviderValidationExecutor.ExecuteAsync(
            client,
            Descriptor,
            decryptedSecret,
            stopwatch,
            ct);
    }
}
