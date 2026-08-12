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

public class SendGridCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "SendGrid";

    public SendGridCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<SendGridCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.sendgrid.com/v3/scopes");
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
            int scopesCount = 0;
            bool hasMailSendScope = false;

            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("scopes", out var scopesArr) && scopesArr.ValueKind == JsonValueKind.Array)
                {
                    scopesCount = scopesArr.GetArrayLength();
                    foreach (var elem in scopesArr.EnumerateArray())
                    {
                        if (elem.GetString() == "mail.send")
                        {
                            hasMailSendScope = true;
                            break;
                        }
                    }
                }
            }
            catch { }

            var evidence = JsonSerializer.Serialize(new { scopesCount, hasMailSendScope, latencyMs = stopwatch.ElapsedMilliseconds });
            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — SendGrid API Key Scopes Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid SendGrid API Key", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 Forbidden — SendGrid Key lacking scopes endpoint permission", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — SendGrid rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
