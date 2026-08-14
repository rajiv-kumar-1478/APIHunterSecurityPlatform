namespace Platform.Application.Configuration;

/// <summary>
/// Configuration options for the CampaignSchedulerWorker background service.
/// Bind from "CampaignScheduler" section in appsettings.json.
/// </summary>
public class CampaignSchedulerOptions
{
    public const string SectionName = "CampaignScheduler";

    /// <summary>
    /// Master switch. Set false to disable all scheduler dispatch without redeploying.
    /// </summary>
    public bool GlobalEnabled { get; set; } = true;

    /// <summary>
    /// How often the scheduler polls for due campaigns (seconds). Default: 30s.
    /// </summary>
    public int TickIntervalSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum campaigns evaluated per tick to bound the scheduler''s DB query cost.
    /// </summary>
    public int MaxCampaignsPerTick { get; set; } = 50;

    /// <summary>
    /// How long a Running job may have no heartbeat before recovery considers it stuck (minutes).
    /// Default: 60 minutes.
    /// </summary>
    public int StuckJobThresholdMinutes { get; set; } = 60;

    /// <summary>
    /// How often the recovery loop runs (seconds). Default: 5 minutes.
    /// </summary>
    public int RecoveryIntervalSeconds { get; set; } = 300;

    /// <summary>
    /// How frequently a running scan job must write its heartbeat (seconds).
    /// GenericScanWorker uses this to pace heartbeat updates.
    /// </summary>
    public int HeartbeatIntervalSeconds { get; set; } = 120;
}
