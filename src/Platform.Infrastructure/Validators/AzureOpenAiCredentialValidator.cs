using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

/// <summary>
/// Authoritative credential validator for Azure OpenAI.
///
/// Unlike providers with a single global host, Azure OpenAI requires customer-specific
/// resource endpoints (https://{resource}.openai.azure.com).
///
/// Security invariants enforced:
/// 1. Domain allowlisting: Host MUST match ^[a-zA-Z0-9-]+\.openai\.azure\.(com|us)$
/// 2. SSRF screening: All resolved A/AAAA DNS records screened via SsrfProtectionService
/// 3. IP socket pinning (DEC-015): TCP socket connects to validated IP; TLS SNI preserves hostname
/// 4. Tenant isolation: Endpoint resolved strictly from candidate's tenant configuration
/// 5. Zero secret leakage: Key applied only to api-key header in transient method scope
/// </summary>
public sealed class AzureOpenAiCredentialValidator : BaseCredentialValidator
{
    public const string AzureOpenAiProviderName = "AzureOpenAI";

    private static readonly Regex AzureOpenAiDomainRegex = new(
        @"^[a-zA-Z0-9-]+\.openai\.azure\.(com|us)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IPlatformDbContext _dbContext;

    public override string ProviderName => AzureOpenAiProviderName;
    public override string ValidatorVersion => "1.0.0";

    public AzureOpenAiCredentialValidator(
        IPlatformDbContext dbContext,
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<AzureOpenAiCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
    }

    public override bool CanValidate(CredentialCandidate candidate)
    {
        if (candidate == null) return false;
        return string.Equals(candidate.CredentialType, ProviderName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(candidate.CredentialType, "Azure_OpenAI", StringComparison.OrdinalIgnoreCase);
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(
        CredentialCandidate candidate,
        string decryptedSecret,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        // 1. Resolve tenant's Azure OpenAI provider setting
        var setting = await _dbContext.TenantProviderSettings
            .AsNoTracking()
            .FirstOrDefaultAsync(
                s => s.ProviderName == AzureOpenAiProviderName && s.IsEnabled,
                ct);

        if (setting == null || !setting.IsEnabled || string.IsNullOrWhiteSpace(setting.ResourceEndpointUrl))
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.Unsupported,
                ValidationConfidence.Indeterminate,
                "Azure OpenAI resource endpoint is not configured for this tenant. Configure your Azure resource URL under Settings.",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 2. Parse and validate URL structure
        if (!Uri.TryCreate(setting.ResourceEndpointUrl.Trim(), UriKind.Absolute, out var endpointUri)
            || !endpointUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.BlockedByPolicy,
                ValidationConfidence.Strong,
                "Configured Azure OpenAI endpoint must be a valid absolute HTTPS URL.",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 3. Enforce Azure OpenAI domain regex constraint
        if (!AzureOpenAiDomainRegex.IsMatch(endpointUri.Host))
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.BlockedByPolicy,
                ValidationConfidence.Strong,
                $"Configured Azure OpenAI host '{endpointUri.Host}' is not an authorized *.openai.azure.com domain.",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 4. Validate resolved IPs against SSRF private/metadata CIDR blocklist
        var ssrfResult = await _ssrfProtectionService.ValidateUriAsync(endpointUri, ct);
        if (!ssrfResult.IsAllowed || !ssrfResult.ValidatedIpAddresses.Any())
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.BlockedByPolicy,
                ValidationConfidence.Strong,
                $"SSRF Protection blocked Azure OpenAI endpoint '{endpointUri.Host}': {ssrfResult.DenialReason}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 5. Connect via pinned IP handler (DEC-015)
        var targetIp = ssrfResult.ValidatedIpAddresses.First();
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(targetIp, context.DnsEndPoint.Port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

        using var client = new HttpClient(handler, disposeHandler: true);

        // Standard Azure OpenAI model enumeration endpoint
        var apiVersion = string.IsNullOrWhiteSpace(setting.ApiVersion) ? "2023-05-15" : setting.ApiVersion.Trim();
        var requestUrl = $"{endpointUri.Scheme}://{endpointUri.Host}/openai/models?api-version={apiVersion}";

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        request.Headers.TryAddWithoutValidation("api-key", decryptedSecret);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.Unavailable,
                ValidationConfidence.Indeterminate,
                $"Network error contacting Azure OpenAI endpoint: {ex.Message}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        using (response)
        {
            stopwatch.Stop();
            int statusCode = (int)response.StatusCode;

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var body = await response.Content.ReadAsStringAsync(ct);
                int modelCount = 0;
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("data", out var dataElem) && dataElem.ValueKind == JsonValueKind.Array)
                    {
                        modelCount = dataElem.GetArrayLength();
                    }
                }
                catch
                {
                    // JSON parsing failed, but HTTP 200 with api-key confirms valid credential.
                }

                var safeEvidence = JsonSerializer.Serialize(new
                {
                    statusCode = 200,
                    provider = AzureOpenAiProviderName,
                    modelCount,
                    latencyMs = stopwatch.ElapsedMilliseconds
                });

                return new ValidationResultDto(
                    ValidationStatus.Valid,
                    ValidationConfidence.Strong,
                    $"Azure OpenAI credential is valid ({modelCount} models enumerated).",
                    safeEvidence,
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return new ValidationResultDto(
                    ValidationStatus.Invalid,
                    ValidationConfidence.Strong,
                    "HTTP 401 Unauthorized — Azure OpenAI rejected the api-key.",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                return new ValidationResultDto(
                    ValidationStatus.ValidInsufficientScope,
                    ValidationConfidence.Strong,
                    "HTTP 403 Forbidden — Azure OpenAI credential valid but has insufficient permissions.",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return new ValidationResultDto(
                    ValidationStatus.RateLimited,
                    ValidationConfidence.Strong,
                    "HTTP 429 Too Many Requests — Azure OpenAI rate limit exceeded.",
                    "{}",
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            return new ValidationResultDto(
                ValidationStatus.Invalid,
                ValidationConfidence.Strong,
                $"Azure OpenAI returned unexpected HTTP status {statusCode}.",
                "{}",
                stopwatch.ElapsedMilliseconds,
                statusCode);
        }
    }
}
