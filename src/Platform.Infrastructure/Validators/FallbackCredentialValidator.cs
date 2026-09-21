using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Security;

namespace Platform.Infrastructure.Validators;

public class FallbackCredentialValidator : BaseCredentialValidator
{
    private readonly IServiceProvider _serviceProvider;
    public override string ProviderName => "Fallback";
    public override string ValidatorVersion => "2.0.0-AI-Dynamic";

    public FallbackCredentialValidator(
        SsrfProtectionService ssrfProtectionService,
        IOptions<ValidationPolicyOptions> policyOptions,
        IServiceProvider serviceProvider,
        ILogger<FallbackCredentialValidator> logger)
        : base(ssrfProtectionService, policyOptions, logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    }

    public override bool CanValidate(CredentialCandidate candidate)
    {
        // Fallback validator catches any unsupported or unlisted credential type
        return true;
    }

    protected override async Task<ValidationResultDto> ExecuteValidationAsync(
        CredentialCandidate candidate,
        string decryptedSecret,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        string candidateType = candidate.CredentialType ?? "Unknown";

        // 1. Resolve scoped services for AI analysis and context
        using var scope = _serviceProvider.CreateScope();
        var aiRouter = scope.ServiceProvider.GetService<IAiModelRouter>();
        var dbContext = scope.ServiceProvider.GetService<IPlatformDbContext>();

        if (aiRouter == null)
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.Unsupported,
                ValidationConfidence.Strong,
                $"Credential type '{candidateType}' has no hardcoded validator and AI router is not registered.",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 2. Fetch code occurrence context if available
        string lineContext = candidate.CredentialType ?? "Unknown";
        string filePath = "unknown";
        if (dbContext != null)
        {
            try
            {
                var occurrence = await dbContext.CandidateOccurrences
                    .Include(o => o.SnapshotFile)
                    .FirstOrDefaultAsync(o => o.CandidateId == candidate.Id, ct);

                if (occurrence != null)
                {
                    filePath = occurrence.SnapshotFile?.FilePath ?? "unknown";
                    lineContext = occurrence.LineContentRedacted ?? occurrence.LineNumber.ToString();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed loading occurrence context for candidate {CandidateId}", candidate.Id);
            }
        }

        // 3. Autonomous AI Dynamic Validation Request
        var prompt = new AiPromptRequest(
            SystemPrompt: "You are APIHunter's Autonomous Security Live Validation Engine. " +
                          "Your task is to inspect an unlisted or custom credential found in code or an environment file (.env), " +
                          "identify the provider/service, and construct the precise HTTP authentication check request " +
                          "to verify whether this credential is active or revoked. " +
                          "Respond strictly with valid JSON conforming to the requested schema. No conversational text.",
            UserPrompt: $"A credential candidate was found in repository file '{filePath}'.\n" +
                        $"Credential Type / Label: '{candidateType}'\n" +
                        $"Context Line: '{lineContext}'\n" +
                        $"Masked Secret: '{candidate.MaskedValue}'\n\n" +
                        "Task:\n" +
                        "1. Identify the likely service or API provider (e.g. Kiro, Supabase, Pinecone, Resend, TogetherAI, etc.).\n" +
                        "2. Determine the canonical public HTTPS documentation endpoint to safely test authentication (e.g. GET /v1/user, GET /v1/models, or equivalent auth check).\n" +
                        "3. Specify HTTP method (GET or POST), Request URL (must be public HTTPS), header name (e.g. 'Authorization', 'x-api-key') and value format ('Bearer {secret}', '{secret}', etc.).\n" +
                        "4. Specify expected HTTP status codes for active key (e.g. [200, 201, 204]) and revoked key (e.g. [401, 403]).\n\n" +
                        "Respond with ONLY a JSON object:\n" +
                        "{\n" +
                        "  \"providerName\": \"...\",\n" +
                        "  \"requestUrl\": \"https://...\",\n" +
                        "  \"httpMethod\": \"GET\",\n" +
                        "  \"authHeaderName\": \"Authorization\",\n" +
                        "  \"authHeaderFormat\": \"Bearer {secret}\",\n" +
                        "  \"customHeaders\": {},\n" +
                        "  \"body\": null,\n" +
                        "  \"activeStatusCodes\": [200, 201, 204],\n" +
                        "  \"revokedStatusCodes\": [401, 403]\n" +
                        "}",
            Temperature: 0.1,
            RequireJsonOutput: true);

        AiValidationSpec? spec = null;
        try
        {
            var (aiResponse, _, _) = await aiRouter.ExecuteWithFallbackAsync(prompt, ct: ct);
            if (aiResponse.IsSuccess && !string.IsNullOrWhiteSpace(aiResponse.RawResponseContent))
            {
                var json = aiResponse.NormalizedJsonContent ?? aiResponse.RawResponseContent;
                var start = json.IndexOf('{');
                var end = json.LastIndexOf('}');
                if (start >= 0 && end > start)
                {
                    json = json.Substring(start, end - start + 1);
                    spec = JsonSerializer.Deserialize<AiValidationSpec>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Autonomous AI model routing failed for candidate {CandidateId}", candidate.Id);
        }

        if (spec == null || string.IsNullOrWhiteSpace(spec.RequestUrl) ||
            !Uri.TryCreate(spec.RequestUrl, UriKind.Absolute, out var targetUri) ||
            !targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            stopwatch.Stop();
            return new ValidationResultDto(
                ValidationStatus.Unsupported,
                ValidationConfidence.Strong,
                $"Autonomous AI Dynamic Validation could not infer a verifiable public endpoint for '{candidateType}'",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }

        // 4. Safe Dynamic SSRF-Protected Outbound Execution
        try
        {
            var handler = _ssrfProtectionService.CreateDynamicSsrfHandler();
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            var method = new HttpMethod(spec.HttpMethod?.ToUpperInvariant() ?? "GET");
            using var request = new HttpRequestMessage(method, targetUri);

            // Auth header
            var headerName = string.IsNullOrWhiteSpace(spec.AuthHeaderName) ? "Authorization" : spec.AuthHeaderName;
            var headerFormat = string.IsNullOrWhiteSpace(spec.AuthHeaderFormat) ? "Bearer {secret}" : spec.AuthHeaderFormat;
            var headerVal = headerFormat.Replace("{secret}", decryptedSecret);
            request.Headers.TryAddWithoutValidation(headerName, headerVal);

            // Custom headers
            if (spec.CustomHeaders != null)
            {
                foreach (var (k, v) in spec.CustomHeaders)
                {
                    request.Headers.TryAddWithoutValidation(k, v);
                }
            }

            // Body if present
            if (!string.IsNullOrWhiteSpace(spec.Body) && method != HttpMethod.Get)
            {
                request.Content = new StringContent(spec.Body, Encoding.UTF8, "application/json");
            }

            var response = await client.SendAsync(request, ct);
            stopwatch.Stop();

            int statusCode = (int)response.StatusCode;
            var activeCodes = spec.ActiveStatusCodes ?? new List<int> { 200, 201, 204 };
            var revokedCodes = spec.RevokedStatusCodes ?? new List<int> { 401, 403 };

            var evidence = new
            {
                autonomousAiValidation = true,
                inferredProvider = spec.ProviderName,
                targetHost = targetUri.Host,
                targetEndpoint = targetUri.AbsolutePath,
                httpMethod = method.Method,
                httpStatusCode = statusCode,
                latencyMs = stopwatch.ElapsedMilliseconds
            };
            string safeEvidenceJson = JsonSerializer.Serialize(evidence);

            if (activeCodes.Contains(statusCode) || (statusCode >= 200 && statusCode <= 299))
            {
                return new ValidationResultDto(
                    ValidationStatus.Valid,
                    ValidationConfidence.Confirmed,
                    $"Autonomous AI Live Validation: Credential confirmed ACTIVE against {spec.ProviderName} ({targetUri.Host}).",
                    safeEvidenceJson,
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            if (revokedCodes.Contains(statusCode) || statusCode == 401 || statusCode == 403)
            {
                return new ValidationResultDto(
                    ValidationStatus.Revoked,
                    ValidationConfidence.Confirmed,
                    $"Autonomous AI Live Validation: Credential rejected/revoked by {spec.ProviderName} ({targetUri.Host}). Status: {statusCode}.",
                    safeEvidenceJson,
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            if (statusCode == 429)
            {
                return new ValidationResultDto(
                    ValidationStatus.RateLimited,
                    ValidationConfidence.Strong,
                    $"Autonomous AI Live Validation: Rate limited by {spec.ProviderName} (HTTP 429).",
                    safeEvidenceJson,
                    stopwatch.ElapsedMilliseconds,
                    statusCode);
            }

            return new ValidationResultDto(
                ValidationStatus.Unknown,
                ValidationConfidence.Indeterminate,
                $"Autonomous AI Live Validation: Received HTTP {statusCode} from {targetUri.Host}.",
                safeEvidenceJson,
                stopwatch.ElapsedMilliseconds,
                statusCode);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            _logger.LogWarning(ex, "Autonomous AI validation request to {Host} failed", targetUri.Host);
            return new ValidationResultDto(
                ValidationStatus.Unavailable,
                ValidationConfidence.Indeterminate,
                $"Autonomous AI Live Validation: Connection to {targetUri.Host} failed: {ex.Message}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Unexpected error during Autonomous AI validation for {Host}", targetUri.Host);
            return new ValidationResultDto(
                ValidationStatus.ValidationError,
                ValidationConfidence.Indeterminate,
                $"Autonomous AI Live Validation error: {ex.Message}",
                "{}",
                stopwatch.ElapsedMilliseconds);
        }
    }

    private sealed class AiValidationSpec
    {
        public string? ProviderName { get; set; }
        public string? RequestUrl { get; set; }
        public string? HttpMethod { get; set; }
        public string? AuthHeaderName { get; set; }
        public string? AuthHeaderFormat { get; set; }
        public Dictionary<string, string>? CustomHeaders { get; set; }
        public string? Body { get; set; }
        public List<int>? ActiveStatusCodes { get; set; }
        public List<int>? RevokedStatusCodes { get; set; }
    }
}

