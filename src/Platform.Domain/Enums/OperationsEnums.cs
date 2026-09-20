namespace Platform.Domain.Enums;

public enum IncidentSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum IncidentCategory
{
    WorkerHeartbeatLost = 0,
    LeaseDeadlock = 1,
    DatabaseDegraded = 2,
    CampaignStall = 3,
    AiProviderQuotaExhausted = 4,
    ConsecutiveJobFailures = 5
}

public enum IncidentStatus
{
    Detected = 0,
    Investigating = 1,
    Mitigated = 2,
    Resolved = 3,
    Suppressed = 4
}
