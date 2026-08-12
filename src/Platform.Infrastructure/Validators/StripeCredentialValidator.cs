using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public class StripeCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "Stripe";

    public StripeCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<StripeCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        // whsec_ (webhook signing secrets) and pk_ (publishable keys) cannot be validated via /v1/balance API
        if (decryptedSecret.StartsWith("whsec_", StringComparison.OrdinalIgnoreCase))
        {
            stopwatch.Stop();
            var evidence = JsonSerializer.Serialize(new { keyType = "WebhookSecret", notice = "Webhook signing secrets require signed payload verification" });
            return new ValidationResultDto(ValidationStatus.Unsupported, ValidationConfidence.Strong, "Stripe Webhook Secret candidate cannot be validated via REST balance API", evidence, stopwatch.ElapsedMilliseconds);
        }

        if (decryptedSecret.StartsWith("pk_", StringComparison.OrdinalIgnoreCase))
        {
            stopwatch.Stop();
            var evidence = JsonSerializer.Serialize(new { keyType = "PublishableKey", notice = "Publishable keys are public client identifiers" });
            return new ValidationResultDto(ValidationStatus.Unsupported, ValidationConfidence.Strong, "Stripe Publishable Key candidate is public client identifier", evidence, stopwatch.ElapsedMilliseconds);
        }

        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.stripe.com/v1/balance");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", decryptedSecret);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return new ValidationResultDto(ValidationStatus.Unavailable, ValidationConfidence.Indeterminate, $"Network error: {ex.Message}", "{}", stopwatch.ElapsedMilliseconds);
        }

        stopwatch.Stop();
        int statusCode = (int)response.StatusCode;

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            bool livemode = decryptedSecret.StartsWith("sk_live_", StringComparison.OrdinalIgnoreCase) || decryptedSecret.StartsWith("rk_live_", StringComparison.OrdinalIgnoreCase);

            var evidence = JsonSerializer.Serialize(new { livemode, keyPrefix = decryptedSecret.Length >= 7 ? decryptedSecret[..7] : "sk_", latencyMs = stopwatch.ElapsedMilliseconds });
            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — Stripe Balance Endpoint Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid Stripe Key", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 Forbidden — Stripe Restricted Key lacking balance permissions", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — Stripe rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
