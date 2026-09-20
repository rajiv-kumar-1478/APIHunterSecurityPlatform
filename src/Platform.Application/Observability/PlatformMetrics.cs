using System.Diagnostics.Metrics;

namespace Platform.Application.Observability;

public static class PlatformMetrics
{
    public const string MeterName = "APIHunter.SecurityPlatform";
    public const string MeterVersion = "1.0.0";

    private static readonly Meter Meter = new(MeterName, MeterVersion);

    // Job counters
    public static readonly Counter<long> JobsDispatched = Meter.CreateCounter<long>(
        "security_jobs_dispatched_total",
        "jobs",
        "Total number of security scan and analysis jobs dispatched");

    public static readonly Counter<long> JobsCompleted = Meter.CreateCounter<long>(
        "security_jobs_completed_total",
        "jobs",
        "Total number of security scan and analysis jobs completed successfully");

    public static readonly Counter<long> JobsFailed = Meter.CreateCounter<long>(
        "security_jobs_failed_total",
        "jobs",
        "Total number of security scan and analysis jobs failed");

    public static readonly Counter<long> JobsTimedOut = Meter.CreateCounter<long>(
        "security_jobs_timed_out_total",
        "jobs",
        "Total number of security scan and analysis jobs timed out");

    // Incident counters
    public static readonly Counter<long> IncidentsDetected = Meter.CreateCounter<long>(
        "operational_incidents_detected_total",
        "incidents",
        "Total operational incidents detected by the incident engine");

    public static readonly Counter<long> IncidentsRecovered = Meter.CreateCounter<long>(
        "operational_incidents_recovered_total",
        "incidents",
        "Total operational incidents automatically recovered or self-healed");

    // Duration histograms
    public static readonly Histogram<double> JobExecutionDuration = Meter.CreateHistogram<double>(
        "security_job_execution_duration_seconds",
        "s",
        "Duration of security job execution in seconds");

    public static readonly Histogram<double> AiDiagnosisDuration = Meter.CreateHistogram<double>(
        "ai_diagnosis_duration_seconds",
        "s",
        "Duration of AI operational diagnosis completion in seconds");

    public static readonly Histogram<double> CredentialValidationDuration = Meter.CreateHistogram<double>(
        "credential_validation_duration_seconds",
        "s",
        "Duration of live credential validation in seconds");

    // Trackable gauges
    private static int _activeWorkersCount;
    private static int _pendingQueueDepth;
    private static int _overdueCampaignsCount;

    public static void SetActiveWorkers(int count) => Interlocked.Exchange(ref _activeWorkersCount, count);
    public static void SetPendingQueueDepth(int depth) => Interlocked.Exchange(ref _pendingQueueDepth, depth);
    public static void SetOverdueCampaigns(int count) => Interlocked.Exchange(ref _overdueCampaignsCount, count);

    public static int CurrentActiveWorkers => Volatile.Read(ref _activeWorkersCount);
    public static int CurrentPendingQueueDepth => Volatile.Read(ref _pendingQueueDepth);
    public static int CurrentOverdueCampaigns => Volatile.Read(ref _overdueCampaignsCount);

    static PlatformMetrics()
    {
        Meter.CreateObservableGauge("worker_active_count", () => Volatile.Read(ref _activeWorkersCount), "workers", "Number of currently active worker nodes");
        Meter.CreateObservableGauge("queue_pending_depth", () => Volatile.Read(ref _pendingQueueDepth), "jobs", "Number of jobs pending execution in queue");
        Meter.CreateObservableGauge("campaign_overdue_count", () => Volatile.Read(ref _overdueCampaignsCount), "campaigns", "Number of scan campaigns overdue for execution");
    }
}
