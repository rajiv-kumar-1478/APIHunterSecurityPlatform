using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public class MailgunCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "Mailgun";

    public MailgunCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<MailgunCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.mailgun.net/v5/users/me");

        string basicAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{decryptedSecret}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);

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
            string userEmail = "Unknown";
            string accountStatus = "Active";

            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("user", out var uObj))
                {
                    if (uObj.TryGetProperty("email", out var eProp)) userEmail = eProp.GetString() ?? "Unknown";
                }
            }
            catch { }

            var evidence = JsonSerializer.Serialize(new { userEmail, accountStatus, latencyMs = stopwatch.ElapsedMilliseconds });
            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — Mailgun User Identity Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid Mailgun Key", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 Forbidden — Mailgun permission restriction", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — Mailgun rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
