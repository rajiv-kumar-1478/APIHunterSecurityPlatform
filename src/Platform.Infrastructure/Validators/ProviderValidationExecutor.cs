using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Platform.Application.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Validators;

/// <summary>
/// Single implementation of the provider credential-validation request/response contract.
///
/// This exists as a separate, directly testable unit because every declarative provider
/// shares identical HTTP status semantics. Testing the mapping once — rather than copying it
/// per provider — keeps the network-path branches genuinely covered.
///
/// Secret-handling rules enforced here:
/// - the secret is only ever written to a request header, never to a log, evidence payload,
///   or response classification;
/// - response bodies are parsed for a single expected property and otherwise discarded;
/// - <c>SafeEvidenceJson</c> carries only counts, booleans, and latency.
/// </summary>
public static class ProviderValidationExecutor
{
    public static async Task<ValidationResultDto> ExecuteAsync(
        HttpClient client,
        ProviderValidationDescriptor descriptor,
        string decryptedSecret,
        Stopwatch stopwatch,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(stopwatch);

        using var request = new HttpRequestMessage(descriptor.Method, descriptor.RequestUri);
        ApplyAuthentication(request, descriptor, decryptedSecret);

        if (descriptor.AdditionalHeaders != null)
        {
            foreach (var header in descriptor.AdditionalHeaders)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        if (!string.IsNullOrWhiteSpace(descriptor.JsonBody))
        {
            request.Content = new StringContent(descriptor.JsonBody, Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            // Also the path taken when SSRF protection blocks the connection.
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.Unavailable,
                ValidationConfidence.Indeterminate,
                $"Network error: {ex.Message}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        using (response)
        {
            // Rate limiting is checked before success because some providers answer 429
            // with a conventional body.
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                stopwatch.Stop();
                return new ValidationResultDto(
                    ValidationStatus.RateLimited,
                    ValidationConfidence.Strong,
                    "HTTP 429 Too Many Requests — provider rate limited",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    (int)response.StatusCode,
                    ResolveRetryAfterUtc(response));
            }

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var body = await response.Content.ReadAsStringAsync(ct);
                stopwatch.Stop();
                return ClassifySuccess(descriptor, body, stopwatch.ElapsedMilliseconds, (int)response.StatusCode);
            }

            stopwatch.Stop();
            int statusCode = (int)response.StatusCode;

            return response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => new ValidationResultDto(
                    ValidationStatus.Invalid,
                    ValidationConfidence.Confirmed,
                    "HTTP 401 Unauthorized — credential rejected by provider",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode),

                HttpStatusCode.Forbidden => new ValidationResultDto(
                    ValidationStatus.ValidInsufficientScope,
                    ValidationConfidence.Strong,
                    "HTTP 403 Forbidden — credential lacks required scope or permission",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode),

                _ => new ValidationResultDto(
                    ValidationStatus.ValidationError,
                    ValidationConfidence.Indeterminate,
                    $"HTTP {statusCode} — Unexpected response",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode)
            };
        }
    }

    private static void ApplyAuthentication(
        HttpRequestMessage request,
        ProviderValidationDescriptor descriptor,
        string decryptedSecret)
    {
        switch (descriptor.AuthScheme)
        {
            case ProviderAuthScheme.BearerAuthorization:
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", decryptedSecret);
                break;

            case ProviderAuthScheme.TokenAuthorization:
                request.Headers.Authorization = new AuthenticationHeaderValue("Token", decryptedSecret);
                break;

            case ProviderAuthScheme.KeyAuthorization:
                request.Headers.Authorization = new AuthenticationHeaderValue("Key", decryptedSecret);
                break;

            case ProviderAuthScheme.RawAuthorization:
                request.Headers.TryAddWithoutValidation("Authorization", decryptedSecret);
                break;

            case ProviderAuthScheme.CustomHeader:
                if (string.IsNullOrWhiteSpace(descriptor.AuthHeaderName))
                {
                    throw new InvalidOperationException(
                        "A CustomHeader authentication scheme requires AuthHeaderName to be set.");
                }

                request.Headers.TryAddWithoutValidation(descriptor.AuthHeaderName, decryptedSecret);
                break;

            default:
                throw new InvalidOperationException(
                    $"Unsupported provider authentication scheme '{descriptor.AuthScheme}'.");
        }
    }

    private static ValidationResultDto ClassifySuccess(
        ProviderValidationDescriptor descriptor,
        string body,
        long latencyMs,
        int statusCode)
    {
        if (string.IsNullOrWhiteSpace(descriptor.SuccessJsonProperty))
        {
            return new ValidationResultDto(
                ValidationStatus.Valid,
                ValidationConfidence.Confirmed,
                $"HTTP 200 OK — {descriptor.SuccessLabel}",
                JsonSerializer.Serialize(new { latencyMs }),
                latencyMs,
                statusCode);
        }

        JsonElement property;
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty(descriptor.SuccessJsonProperty, out property))
            {
                return new ValidationResultDto(
                    ValidationStatus.ValidationError,
                    ValidationConfidence.Indeterminate,
                    $"HTTP 200 — Response did not contain the expected '{descriptor.SuccessJsonProperty}' field",
                    "{}",
                    latencyMs,
                    statusCode);
            }

            // A provider that answers 200 with an explicit false verification flag is a
            // definitive rejection, not a transport problem.
            if (property.ValueKind == JsonValueKind.False)
            {
                return new ValidationResultDto(
                    ValidationStatus.Invalid,
                    ValidationConfidence.Confirmed,
                    $"HTTP 200 — Provider reported '{descriptor.SuccessJsonProperty}' as false",
                    "{}",
                    latencyMs,
                    statusCode);
            }

            var itemCount = property.ValueKind == JsonValueKind.Array
                ? property.GetArrayLength()
                : (int?)null;

            var evidence = itemCount.HasValue
                ? JsonSerializer.Serialize(new { itemCount = itemCount.Value, latencyMs })
                : JsonSerializer.Serialize(new { verifiedField = descriptor.SuccessJsonProperty, latencyMs });

            return new ValidationResultDto(
                ValidationStatus.Valid,
                ValidationConfidence.Confirmed,
                $"HTTP 200 OK — {descriptor.SuccessLabel}",
                evidence,
                latencyMs,
                statusCode);
        }
        catch (JsonException)
        {
            return new ValidationResultDto(
                ValidationStatus.ValidationError,
                ValidationConfidence.Indeterminate,
                "HTTP 200 — Response body was not valid JSON",
                "{}",
                latencyMs,
                statusCode);
        }
    }

    private static DateTime? ResolveRetryAfterUtc(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter?.Date.HasValue == true)
        {
            return response.Headers.RetryAfter.Date.Value.UtcDateTime;
        }

        if (response.Headers.RetryAfter?.Delta.HasValue == true)
        {
            return DateTime.UtcNow.Add(response.Headers.RetryAfter.Delta.Value);
        }

        return null;
    }
}
