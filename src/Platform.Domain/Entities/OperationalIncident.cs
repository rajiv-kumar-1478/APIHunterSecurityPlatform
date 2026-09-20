using System.ComponentModel.DataAnnotations;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class OperationalIncident
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// TenantId is nullable for platform-wide infrastructure incidents (e.g. general worker crash or DB deadlock).
    /// </summary>
    public Guid? TenantId { get; set; }

    public IncidentSeverity Severity { get; set; } = IncidentSeverity.Medium;

    public IncidentCategory Category { get; set; }

    public IncidentStatus Status { get; set; } = IncidentStatus.Detected;

    [MaxLength(256)]
    public string Title { get; set; } = string.Empty;

    [MaxLength(256)]
    public string Fingerprint { get; set; } = string.Empty;

    public DateTime FirstObservedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime LastObservedAtUtc { get; set; } = DateTime.UtcNow;

    public int OccurrenceCount { get; set; } = 1;

    public string? DetailsJson { get; set; }

    [MaxLength(1024)]
    public string? ResolutionNotes { get; set; }

    [MaxLength(512)]
    public string? MitigationActionTaken { get; set; }

    public Guid? AiDiagnosisId { get; set; }

    public AiOperationalDiagnosis? AiDiagnosis { get; set; }
}
