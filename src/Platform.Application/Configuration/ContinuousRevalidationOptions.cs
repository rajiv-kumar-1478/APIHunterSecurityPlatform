namespace Platform.Application.Configuration;

/// <summary>
/// Configuration for the Continuous Revalidation subsystem (Phase 6 Step 6).
/// Bind from appsettings.json section "ContinuousRevalidation".
/// </summary>
public class ContinuousRevalidationOptions
{
    public const string SectionName = "ContinuousRevalidation";

    /// <summary>
    /// Master switch — set to false to pause the entire subsystem without redeployment.
    /// Also respected by SystemSettings["revalidation.global_enabled"].
    /// </summary>
    public bool GlobalEnabled { get; set; } = true;

    /// <summary>
    /// How long the worker sleeps between scheduling passes (seconds). Default: 5 minutes.
    /// </summary>
    public int SchedulingIntervalSeconds { get; set; } = 300;

    /// <summary>
    /// Minimum elapsed time since the last *completed* (non-transient) validation result
    /// before a candidate becomes eligible for re-scheduling. Default: 6 hours.
    /// Transient results (RateLimited, Unavailable, ValidationError) are excluded from
    /// this calculation — only definitive results count.
    /// </summary>
    public int MinRevalidationIntervalHours { get; set; } = 6;

    /// <summary>
    /// Maximum number of candidates to enqueue per scheduling pass (rate control).
    /// </summary>
    public int MaxCandidatesPerPass { get; set; } = 50;

    /// <summary>
    /// How far back to search for unprocessed CredentialValidationResults. Default: 24 hours.
    /// Results older than this window are considered expired for this pass.
    /// </summary>
    public int ResultLookbackHours { get; set; } = 24;

    /// <summary>
    /// If a ProcessingClaimToken was set more than this many minutes ago without completing,
    /// the claim is considered stale and can be reclaimed. Default: 5 minutes.
    /// </summary>
    public int StaleClaimTimeoutMinutes { get; set; } = 5;
}
