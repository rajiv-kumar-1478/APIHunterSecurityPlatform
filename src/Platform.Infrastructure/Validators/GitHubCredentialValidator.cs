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

public class GitHubCredentialValidator : BaseCredentialValidator
{
    public override string ProviderName => "GitHub";

    public GitHubCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<GitHubCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(CredentialCandidate candidate, string decryptedSecret, Stopwatch stopwatch, CancellationToken ct)
    {
        using var client = CreateSsrfClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", decryptedSecret);
        request.Headers.UserAgent.ParseAdd("APIHunter-Agent/2.0");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version", "2026-03-10");

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
            string login = "Unknown";
            string userType = "User";
            string scopes = "None";

            if (response.Headers.TryGetValues("X-OAuth-Scopes", out var scopeValues))
            {
                scopes = string.Join(", ", scopeValues);
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("login", out var lProp)) login = lProp.GetString() ?? "Unknown";
                if (root.TryGetProperty("type", out var tProp)) userType = tProp.GetString() ?? "User";
            }
            catch { }

            var evidence = JsonSerializer.Serialize(new { login, userType, scopes, latencyMs = stopwatch.ElapsedMilliseconds });
            return new ValidationResultDto(ValidationStatus.Valid, ValidationConfidence.Confirmed, "HTTP 200 OK — GitHub Token Verified", evidence, stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return new ValidationResultDto(ValidationStatus.Invalid, ValidationConfidence.Confirmed, "HTTP 401 Unauthorized — Invalid GitHub Token", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            return new ValidationResultDto(ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong, "HTTP 403 Forbidden — GitHub Token permission restriction or SAML enforcement", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return new ValidationResultDto(ValidationStatus.RateLimited, ValidationConfidence.Strong, "HTTP 429 Too Many Requests — GitHub rate limited", "{}", stopwatch.ElapsedMilliseconds, statusCode);
        }

        return new ValidationResultDto(ValidationStatus.ValidationError, ValidationConfidence.Indeterminate, $"HTTP {statusCode} — Unexpected response", "{}", stopwatch.ElapsedMilliseconds, statusCode);
    }
}
