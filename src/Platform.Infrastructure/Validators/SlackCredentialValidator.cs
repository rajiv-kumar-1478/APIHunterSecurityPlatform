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

public class SlackCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "Slack";

    public SlackCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<SlackCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://slack.com/api/auth.test");
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

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            DateTime? retryAfter = null;
            if (response.Headers.RetryAfter?.Date.HasValue == true)
            {
                retryAfter = response.Headers.RetryAfter.Date.Value.UtcDateTime;
            }
            else if (response.Headers.RetryAfter?.Delta.HasValue == true)
            {
                retryAfter = DateTime.UtcNow.Add(response.Headers.RetryAfter.Delta.Value);
            }

            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — Slack rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode, retryAfter);
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            bool ok = false;
            string error = "Unknown";
            string team = "Unknown";
            string user = "Unknown";
            string botId = "None";

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("ok", out var okProp)) ok = okProp.GetBoolean();
                if (root.TryGetProperty("error", out var errProp)) error = errProp.GetString() ?? "Unknown";
                if (root.TryGetProperty("team", out var teamProp)) team = teamProp.GetString() ?? "Unknown";
                if (root.TryGetProperty("user", out var userProp)) user = userProp.GetString() ?? "Unknown";
                if (root.TryGetProperty("bot_id", out var botProp)) botId = botProp.GetString() ?? "None";
            }
            catch { }

            if (ok)
            {
                var evidence = JsonSerializer.Serialize(new { team, user, botId, latencyMs = stopwatch.ElapsedMilliseconds });
                return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — Slack Token Verified via auth.test", evidence, stopwatch.ElapsedMilliseconds, statusCode);
            }

            if (error.Contains("missing_scope", StringComparison.OrdinalIgnoreCase))
            {
                return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, $"HTTP 200 Slack API Error: {error}", "{}", stopwatch.ElapsedMilliseconds, statusCode);
            }

            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, $"HTTP 200 Slack Invalid Auth: {error}", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid Slack Token", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
