namespace Platform.Application.Configuration;

public class AiRouterOptions
{
    public const string SectionName = "AiRouter";

    /// <summary>
    /// Duration in seconds for transient failure cooldown (e.g. timeouts, network errors, 503).
    /// Default: 120 seconds.
    /// </summary>
    public int TransientCooldownSeconds { get; set; } = 120;
}
