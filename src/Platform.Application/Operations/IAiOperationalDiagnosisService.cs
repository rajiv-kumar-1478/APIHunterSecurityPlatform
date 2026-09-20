using Platform.Domain.Entities;

namespace Platform.Application.Operations;

public interface IAiOperationalDiagnosisService
{
    Task<AiOperationalDiagnosis> DiagnoseIncidentAsync(Guid incidentId, CancellationToken ct = default);
}
