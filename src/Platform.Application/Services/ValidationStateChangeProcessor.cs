using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record ValidationStateChangeReport(int ProcessedCount, int SkippedCount, int ErrorCount);

/// <summary>
/// Processes completed CredentialValidationResults that have not yet had their consequences
/// applied (finding upsert, graph update, risk recalculation, audit event).
///
/// This service is the ONLY writer of:
///   - ProcessedForFindingAtUtc
///   - ProcessingClaimToken / ProcessingClaimedAtUtc
///
/// AUTHORITY BOUNDARY (LOCKED):
///   - Does NOT call SecurityFindingLifecycleService.TransitionFindingStatusAsync()
///   - Does NOT modify FindingStatus via any governance path
///   - Validation truth ≠ finding governance
/// </summary>
public class ValidationStateChangeProcessor(
    IPlatformDbContext dbContext,
    SecurityFindingService findingService,
    SecurityIntelligenceGraphBuilder graphBuilder,
    IOptions<ContinuousRevalidationOptions> options,
    ILogger<ValidationStateChangeProcessor> logger,
    SecurityAlertService? alertService = null)
{
    private readonly ContinuousRevalidationOptions _options = options.Value;
    private readonly SecurityAlertService? _alertService = alertService;

    // ─── Status Category Helpers ─────────────────────────────────────────────

    /// <summary>Definitive active credential.</summary>
    public static bool IsActive(ValidationStatus s) =>
        s is ValidationStatus.Valid or ValidationStatus.ValidInsufficientScope;

    /// <summary>Credential explicitly revoked.</summary>
    public static bool IsRevoked(ValidationStatus s) =>
        s is ValidationStatus.Revoked;

    /// <summary>Credential confirmed expired.</summary>
    public static bool IsExpired(ValidationStatus s) =>
        s is ValidationStatus.Expired;

    /// <summary>Credential definitively inactive (not just transient).</summary>
    public static bool IsInactive(ValidationStatus s) =>
        s is ValidationStatus.Invalid or ValidationStatus.Unsupported or ValidationStatus.BlockedByPolicy;

    /// <summary>
    /// Transient result — does NOT represent a definitive credential state.
    /// MUST NOT participate in state-change detection or scheduling suppression.
    /// </summary>
    public static bool IsTransient(ValidationStatus s) =>
        s is ValidationStatus.RateLimited
            or ValidationStatus.Unavailable
            or ValidationStatus.ValidationError
            or ValidationStatus.Unknown
            or ValidationStatus.Pending;

    // ─── FindingType Mapping ─────────────────────────────────────────────────

    /// <summary>
    /// Maps a definitive ValidationStatus to its corresponding FindingType.
    /// Returns null if no finding should be created (Inactive statuses).
    /// Must only be called with non-transient statuses.
    /// </summary>
    public static FindingType? MapToFindingType(ValidationStatus status) => status switch
    {
        ValidationStatus.Valid => FindingType.ValidatedCredentialExposed,
        ValidationStatus.ValidInsufficientScope => FindingType.ValidatedCredentialExposed,
        ValidationStatus.Expired => FindingType.ExpiredCredentialExposed,
        ValidationStatus.Revoked => FindingType.RevokedCredentialExposed,
        // Invalid / Unsupported / BlockedByPolicy → mark processed, no finding
        _ => null
    };

    // ─── State-Change Category ───────────────────────────────────────────────

    private static string GetStateCategory(ValidationStatus s)
    {
        if (IsActive(s)) return "Active";
        if (IsRevoked(s)) return "Revoked";
        if (IsExpired(s)) return "Expired";
        if (IsInactive(s)) return "Inactive";
        return "Transient"; // should never reach graph logic
    }

    // ─── Public Entry Point ──────────────────────────────────────────────────

    public async Task<ValidationStateChangeReport> ProcessPendingResultsAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var lookbackCutoff = now.AddHours(-_options.ResultLookbackHours);
        var staleClaimCutoff = now.AddMinutes(-_options.StaleClaimTimeoutMinutes);

        // Load candidates: unprocessed OR stale-claimed, within lookback window
        var candidates = await dbContext.CredentialValidationResults
            .Where(r => r.ProcessedForFindingAtUtc == null
                     && r.ValidatedAtUtc >= lookbackCutoff
                     && (r.ProcessingClaimToken == null
                         || r.ProcessingClaimedAtUtc < staleClaimCutoff))
            .OrderBy(r => r.ValidatedAtUtc)
            .ToListAsync(ct);

        int processedCount = 0;
        int skippedCount = 0;
        int errorCount = 0;

        foreach (var result in candidates)
        {
            ct.ThrowIfCancellationRequested();

            // ── Transient results: skip entirely, do not claim ─────────────
            if (IsTransient(result.Status))
            {
                logger.LogDebug("Skipping transient result '{ResultId}' (Status: {Status}).", result.Id, result.Status);
                skippedCount++;
                continue;
            }

            // ── Atomic claim ───────────────────────────────────────────────
            bool claimed = await AttemptClaimAsync(result.Id, ct);
            if (!claimed)
            {
                logger.LogDebug("Result '{ResultId}' was claimed by another worker instance. Skipping.", result.Id);
                skippedCount++;
                continue;
            }

            // ── Per-result processing (isolated — failures do not affect others) ──
            try
            {
                await ProcessSingleResultAsync(result, ct);
                processedCount++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to process CredentialValidationResult '{ResultId}' (CandidateId: '{CandidateId}'). Claim left set for stale-claim retry.",
                    result.Id, result.CandidateId);
                errorCount++;
                // Leave ProcessingClaimToken set — will be reclaimed after StaleClaimTimeoutMinutes
            }
        }

        logger.LogInformation(
            "ValidationStateChangeProcessor pass complete. Processed: {Processed}, Skipped: {Skipped}, Errors: {Errors}.",
            processedCount, skippedCount, errorCount);

        return new ValidationStateChangeReport(processedCount, skippedCount, errorCount);
    }

    // ─── Atomic Claim ────────────────────────────────────────────────────────

    private async Task<bool> AttemptClaimAsync(Guid resultId, CancellationToken ct)
    {
        var claimToken = Guid.NewGuid();
        var now = DateTime.UtcNow;

        // For relational DB: atomic UPDATE WHERE ProcessingClaimToken IS NULL (or stale)
        // For InMemory (tests): optimistic — reload and check, then set
        var dbCtx = (DbContext)dbContext;
        if (dbCtx.Database.IsRelational())
        {
            var rowsAffected = await dbCtx.Database.ExecuteSqlRawAsync(
                """
                UPDATE credential_validation_results
                SET    processing_claim_token    = {0},
                       processing_claimed_at_utc = {1}
                WHERE  id = {2}
                AND    processed_for_finding_at_utc IS NULL
                AND    (processing_claim_token IS NULL
                        OR processing_claimed_at_utc < {3})
                """,
                claimToken, now, resultId, now.AddMinutes(-_options.StaleClaimTimeoutMinutes));

            return rowsAffected > 0;
        }
        else
        {
            // InMemory fallback: reload fresh copy and check optimistically
            var fresh = await dbCtx.Set<CredentialValidationResult>().FindAsync([resultId], ct);
            if (fresh == null) return false;
            if (fresh.ProcessedForFindingAtUtc != null) return false;

            var staleClaimCutoff = now.AddMinutes(-_options.StaleClaimTimeoutMinutes);
            if (fresh.ProcessingClaimToken != null && fresh.ProcessingClaimedAtUtc >= staleClaimCutoff)
                return false;

            fresh.ProcessingClaimToken = claimToken;
            fresh.ProcessingClaimedAtUtc = now;
            await dbCtx.SaveChangesAsync(ct);
            return true;
        }
    }

    // ─── Single-Result Processing ─────────────────────────────────────────────

    private async Task ProcessSingleResultAsync(CredentialValidationResult result, CancellationToken ct)
    {
        // 1. Load candidate for repository context
        var candidate = await dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.Id == result.CandidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate '{result.CandidateId}' not found for result '{result.Id}'.");

        // 2. Determine repository — use candidate's first occurrence for repo context
        var occurrence = await dbContext.CandidateOccurrences
            .Include(o => o.SnapshotFile)
                .ThenInclude(sf => sf.Snapshot)
            .FirstOrDefaultAsync(o => o.CandidateId == candidate.Id, ct);

        Guid? repositoryId = occurrence?.SnapshotFile?.Snapshot?.RepositoryId;

        // 3. Map status to FindingType (null = no finding, just mark processed)
        var findingType = MapToFindingType(result.Status);

        if (findingType.HasValue && repositoryId.HasValue)
        {
            // 4a. Upsert finding (internally recalculates risk + repo risk)
            var finding = await findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                RepositoryId: repositoryId.Value,
                SnapshotId: null,
                FindingType: findingType.Value,
                Severity: RiskSeverity.High,        // RiskEngine will recalculate; use High as seed
                Confidence: FindingConfidence.High,
                Title: BuildFindingTitle(result.Status, candidate.CredentialType),
                Description: BuildFindingDescription(result),
                CoreEntityId: candidate.Id.ToString("N")), ct);

            // 4b. Attach validation result as evidence
            await findingService.AttachEvidenceAsync(finding.Id, new AttachEvidenceRequest(
                EvidenceType: FindingEvidenceType.ValidationResult,
                DiscoverySource: DiscoveryType.CredentialValidation,
                SourceEntityId: result.Id.ToString("N"),
                ValidationResultId: result.Id,
                SafeEvidenceJson: result.SafeEvidenceJson), ct);
        }

        // 5. Detect state change (non-transient previous vs current)
        await DetectAndHandleStateChangeAsync(candidate.Id, result.Status, ct);

        // 5b. Evaluate alert for credential state change (orchestration step)
        if (_alertService != null)
        {
            try
            {
                await _alertService.EvaluateAndAlertForStateChangeAsync(candidate.Id, result.Status, null, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed evaluating state change alert for candidate '{CandidateId}'.", candidate.Id);
            }
        }

        // 6. Audit event
        dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.CredentialRevalidationProcessed,
            ResourceType = "CredentialValidationResult",
            ResourceId = result.Id.ToString(),
            Metadata = System.Text.Json.JsonSerializer.Serialize(new
            {
                candidateId = result.CandidateId,
                status = result.Status.ToString(),
                findingType = findingType?.ToString() ?? "None",
                repositoryId
            }),
            CorrelationId = Guid.NewGuid().ToString()
        });

        // 7. Mark processed and clear claim — atomic with audit event
        result.ProcessedForFindingAtUtc = DateTime.UtcNow;
        result.ProcessingClaimToken = null;
        result.ProcessingClaimedAtUtc = null;

        await dbContext.SaveChangesAsync(ct);

        logger.LogInformation(
            "Processed CredentialValidationResult '{ResultId}' (Status: {Status}, FindingType: {FindingType}, Candidate: '{CandidateId}').",
            result.Id, result.Status, findingType?.ToString() ?? "None", result.CandidateId);
    }

    // ─── State-Change Detection ───────────────────────────────────────────────

    private async Task DetectAndHandleStateChangeAsync(Guid candidateId, ValidationStatus currentStatus, CancellationToken ct)
    {
        // Load the most recent *processed* non-transient result for this candidate (PreviousKnownState)
        var previousKnownResult = await dbContext.CredentialValidationResults
            .Where(r => r.CandidateId == candidateId
                     && r.ProcessedForFindingAtUtc != null
                     && !IsTransient(r.Status))
            .OrderByDescending(r => r.ProcessedForFindingAtUtc)
            .FirstOrDefaultAsync(ct);

        if (previousKnownResult == null) return; // First observation — no comparison

        string previousCategory = GetStateCategory(previousKnownResult.Status);
        string currentCategory = GetStateCategory(currentStatus);

        if (previousCategory == currentCategory) return; // No state change

        // State changed — update the graph node's validation metadata edge
        logger.LogInformation(
            "Credential state change detected for candidate '{CandidateId}': {From} → {To}.",
            candidateId, previousCategory, currentCategory);

        try
        {
            // Update graph edge to reflect new validation state
            var candidateNode = await graphBuilder.GetOrCreateNodeAsync(
                IntelligenceNodeType.CredentialCandidate,
                candidateId.ToString("N"),
                $"Candidate:{candidateId:N}",
                null,       // relatedEntityId
                System.Text.Json.JsonSerializer.Serialize(new
                {
                    validationState = currentCategory,
                    validationStatus = currentStatus.ToString(),
                    stateChangedAtUtc = DateTime.UtcNow
                }),
                ct);

            // Emit SecurityGraphUpdated audit
            dbContext.AuditEvents.Add(new AuditEvent
            {
                EventCode = AuditEventCode.SecurityGraphUpdated,
                ResourceType = "CredentialCandidate",
                ResourceId = candidateId.ToString(),
                Metadata = System.Text.Json.JsonSerializer.Serialize(new
                {
                    previousCategory,
                    currentCategory,
                    validationStatus = currentStatus.ToString(),
                    graphNodeId = candidateNode.Id
                }),
                CorrelationId = Guid.NewGuid().ToString()
            });
        }
        catch (Exception ex)
        {
            // Graph update failure must not block finding/audit processing
            logger.LogWarning(ex,
                "Graph update failed for candidate '{CandidateId}' state change {From} → {To}. Finding processing will continue.",
                candidateId, previousCategory, currentCategory);
        }
    }

    // ─── Title / Description Builders ────────────────────────────────────────

    private static string BuildFindingTitle(ValidationStatus status, string credentialType) => status switch
    {
        ValidationStatus.Valid =>
            $"Active credential exposed: {credentialType}",
        ValidationStatus.ValidInsufficientScope =>
            $"Active credential (insufficient scope) exposed: {credentialType}",
        ValidationStatus.Expired =>
            $"Expired credential found in repository: {credentialType}",
        ValidationStatus.Revoked =>
            $"Revoked credential found in repository: {credentialType}",
        _ => $"Credential exposure detected: {credentialType}"
    };

    private static string BuildFindingDescription(CredentialValidationResult result) =>
        $"Continuous revalidation confirmed this credential ({result.ProviderName}) has status '{result.Status}' " +
        $"as of {result.ValidatedAtUtc:yyyy-MM-dd HH:mm} UTC. " +
        $"Validator: {result.ValidatorVersion}. Attempt #{result.ValidationAttemptNumber}.";
}
