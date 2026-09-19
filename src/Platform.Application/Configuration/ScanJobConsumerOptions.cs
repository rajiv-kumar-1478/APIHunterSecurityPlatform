namespace Platform.Application.Configuration;

/// <summary>
/// Controls the hosted worker that claims and executes queued security scan jobs.
/// Scale-out is achieved by running multiple worker processes; database claim fencing
/// ensures that only one process owns a job.
/// </summary>
public sealed class ScanJobConsumerOptions
{
    public const string SectionName = "ScanJobConsumer";

    /// <summary>
    /// Master switch for queued scan execution.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Delay between empty-queue polls. Values below one second are clamped to one second.
    /// </summary>
    public int PollIntervalSeconds { get; set; } = 3;

    /// <summary>
    /// Number of conditional claim attempts made when another worker wins a claim race.
    /// </summary>
    public int ClaimContentionRetries { get; set; } = 5;
}
