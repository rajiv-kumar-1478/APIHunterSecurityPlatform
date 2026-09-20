using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Operations;

public interface IIncidentEngineService
{
    Task RunDetectionCycleAsync(CancellationToken ct = default);

    Task<OperationalIncident> RecordOrUpdateIncidentAsync(
        string title,
        string fingerprint,
        IncidentCategory category,
        IncidentSeverity severity,
        Guid? tenantId = null,
        string? detailsJson = null,
        CancellationToken ct = default);

    Task<bool> ApplyMitigationAsync(Guid incidentId, string? notes = null, CancellationToken ct = default);

    Task<bool> ResolveIncidentAsync(Guid incidentId, string notes, CancellationToken ct = default);

    Task<List<OperationalIncident>> GetActiveIncidentsAsync(Guid? tenantId = null, CancellationToken ct = default);
}
