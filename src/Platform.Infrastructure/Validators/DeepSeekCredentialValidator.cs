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

public class DeepSeekCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "DeepSeek";

    public DeepSeekCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<DeepSeekCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.deepseek.com/user/balance");
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
            bool isAvailable = true;
            bool hasBalance = false;
            string currency = "CNY";

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("is_available", out var availProp))
                {
                    isAvailable = availProp.GetBoolean();
                }

                if (root.TryGetProperty("balance_infos", out var balanceArr) && balanceArr.ValueKind == JsonValueKind.Array)
                {
                    hasBalance = balanceArr.GetArrayLength() > 0;
                }
            }
            catch { }

            var evidence = JsonSerializer.Serialize(new { isAvailable, hasBalance, currency, latencyMs = stopwatch.ElapsedMilliseconds });

            if (!isAvailable)
            {
                return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 200 OK — DeepSeek key valid but account unavailable/no balance", evidence, stopwatch.ElapsedMilliseconds, statusCode);
            }

            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — DeepSeek API Key Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid DeepSeek API key", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 Forbidden — DeepSeek permission restriction", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — DeepSeek rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
