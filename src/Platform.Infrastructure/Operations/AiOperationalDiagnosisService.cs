using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Observability;
using Platform.Application.Operations;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Operations;

public class AiOperationalDiagnosisService(
    IPlatformDbContext dbContext,
    IAiModelRouter aiModelRouter,
    IOperationalPromptSanitizer promptSanitizer,
    ILogger<AiOperationalDiagnosisService> logger) : IAiOperationalDiagnosisService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public async Task<AiOperationalDiagnosis> DiagnoseIncidentAsync(Guid incidentId, CancellationToken ct = default)
    {
        var incident = await dbContext.OperationalIncidents
            .Include(i => i.AiDiagnosis)
            .FirstOrDefaultAsync(i => i.Id == incidentId, ct)
            ?? throw new KeyNotFoundException($"OperationalIncident with ID {incidentId} not found.");

        using var activity = PlatformTracing.StartAiDiagnosisActivity(incident.Id, "AiRouter");
        var stopwatch = Stopwatch.StartNew();

        // Sanitize all context data before building prompt
        var sanitizedTitle = promptSanitizer.Sanitize(incident.Title);
        var sanitizedDetails = promptSanitizer.Sanitize(incident.DetailsJson);

        var systemPrompt =
            """
            You are the Operations AI Diagnostics Engine for APIHunter Security Platform.
            Analyze the following operational incident and system execution context.
            Identify the primary root cause and provide clear, actionable remediation steps.
            Output ONLY valid JSON matching this schema:
            {
              "rootCause": "<Concise, technically precise explanation of failure>",
              "remediation": "<Specific operator or automated steps to recover>",
              "confidence": <Number between 0.0 and 1.0>
            }
            """;

        var userPrompt =
            $"""
            Incident Details:
            - Category: {incident.Category}
            - Severity: {incident.Severity}
            - Title: {sanitizedTitle}
            - First Observed: {incident.FirstObservedAtUtc:u}
            - Last Observed: {incident.LastObservedAtUtc:u}
            - Occurrences: {incident.OccurrenceCount}
            - Context Data:
            {sanitizedDetails}
            """;

        AiOperationalDiagnosis diagnosis;

        try
        {
            var promptRequest = new AiPromptRequest(systemPrompt, userPrompt, Temperature: 0.1, MaxTokens: 1000, RequireJsonOutput: true);
            var (response, providerName, _) = await aiModelRouter.ExecuteWithFallbackAsync(promptRequest, cancellationToken: ct);

            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.NormalizedJsonContent ?? response.RawResponseContent))
            {
                var contentToParse = response.NormalizedJsonContent ?? response.RawResponseContent;
                var parsed = ParseAiDiagnosisResponse(contentToParse);

                diagnosis = new AiOperationalDiagnosis
                {
                    IncidentId = incident.Id,
                    AnalyzedAtUtc = DateTime.UtcNow,
                    ProviderUsed = providerName,
                    RootCauseSummary = parsed.RootCause,
                    SuggestedRemediation = parsed.Remediation,
                    ConfidenceScore = Math.Clamp(parsed.Confidence, 0.0, 1.0),
                    IsDeterministicFallback = false,
                    SanitizedPrompt = userPrompt
                };
            }
            else
            {
                logger.LogWarning("AI Router returned unsuccessful response for incident {IncidentId}: {Error}. Using deterministic fallback.",
                    incidentId, response.ErrorMessage);
                diagnosis = CreateDeterministicFallback(incident, userPrompt, response.ErrorMessage ?? "AI router returned non-success response");
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Exception querying AI Router for incident {IncidentId}. Falling back to deterministic diagnosis.", incidentId);
            diagnosis = CreateDeterministicFallback(incident, userPrompt, ex.Message);
        }

        stopwatch.Stop();
        PlatformMetrics.AiDiagnosisDuration.Record(stopwatch.Elapsed.TotalSeconds);

        if (incident.AiDiagnosis != null)
        {
            dbContext.AiOperationalDiagnoses.Remove(incident.AiDiagnosis);
        }

        dbContext.AiOperationalDiagnoses.Add(diagnosis);
        incident.AiDiagnosisId = diagnosis.Id;
        incident.AiDiagnosis = diagnosis;
        incident.Status = IncidentStatus.Investigating;

        await dbContext.SaveChangesAsync(ct);
        return diagnosis;
    }

    private static (string RootCause, string Remediation, double Confidence) ParseAiDiagnosisResponse(string jsonContent)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonContent);
            var root = doc.RootElement;

            var rootCause = root.TryGetProperty("rootCause", out var rcProp) ? rcProp.GetString() : null;
            var remediation = root.TryGetProperty("remediation", out var remProp) ? remProp.GetString() : null;
            var confidence = root.TryGetProperty("confidence", out var cProp) && cProp.TryGetDouble(out var conf) ? conf : 0.85;

            if (!string.IsNullOrWhiteSpace(rootCause) && !string.IsNullOrWhiteSpace(remediation))
            {
                return (rootCause, remediation, confidence);
            }
        }
        catch
        {
            // Fall through
        }

        return ("Analysis completed but response format differed from expected schema.",
                "Review worker logs and retry diagnosis.",
                0.70);
    }

    private static AiOperationalDiagnosis CreateDeterministicFallback(OperationalIncident incident, string sanitizedPrompt, string failureReason)
    {
        var (rootCause, remediation, confidence) = incident.Category switch
        {
            IncidentCategory.WorkerHeartbeatLost => (
                "Worker process died, crashed, or was terminated while holding an active scan job lease.",
                "Verify worker node host health, restart the worker container, and trigger automated lease revocation to return jobs to Pending.",
                0.95),

            IncidentCategory.CampaignStall => (
                "Continuous scan campaign missed its scheduled execution window due to worker unavailability or concurrency lock contention.",
                "Verify CampaignSchedulerWorker heartbeat status and trigger campaign schedule cursor reset to current time.",
                0.90),

            IncidentCategory.LeaseDeadlock => (
                "Concurrent worker dispatchers encountered lock contention or query timeout during queue claim (SKIP LOCKED).",
                "Review PostgreSQL connection pool saturation and active queries in pg_stat_activity.",
                0.90),

            IncidentCategory.AiProviderQuotaExhausted => (
                "Configured AI provider rejected requests due to rate limits or exhausted credit quotas.",
                "Switch to secondary provider in AiRouter pool or increase provider concurrency limits.",
                0.95),

            IncidentCategory.ConsecutiveJobFailures => (
                "Target repository scanner encountered recurring execution errors across multiple scan attempts.",
                "Verify scanner container runtime dependencies, target connectivity, and repository clone credentials.",
                0.85),

            _ => (
                $"Incident occurred during background processing: {failureReason}",
                "Review application error logs and retry the failed operation.",
                0.70)
        };

        return new AiOperationalDiagnosis
        {
            IncidentId = incident.Id,
            AnalyzedAtUtc = DateTime.UtcNow,
            ProviderUsed = "DeterministicFallbackEngine",
            RootCauseSummary = rootCause,
            SuggestedRemediation = remediation,
            ConfidenceScore = confidence,
            IsDeterministicFallback = true,
            SanitizedPrompt = sanitizedPrompt
        };
    }
}
