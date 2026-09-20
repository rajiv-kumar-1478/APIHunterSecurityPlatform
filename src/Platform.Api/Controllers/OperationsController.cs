using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Observability;
using Platform.Application.Operations;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/operations")]
[Authorize(Policy = "PlatformAdmin")]
public class OperationsController(
    IIncidentEngineService incidentEngine,
    IAiOperationalDiagnosisService aiDiagnosisService,
    IPlatformDbContext dbContext,
    ITenantContext tenantContext,
    ILogger<OperationsController> logger) : ControllerBase
{
    [HttpGet("health-overview")]
    public async Task<IActionResult> GetHealthOverview(CancellationToken ct)
    {
        var tenantId = tenantContext.TenantId;
        var now = DateTime.UtcNow;

        var activeIncidents = await dbContext.OperationalIncidents
            .CountAsync(i => (i.TenantId == tenantId || i.TenantId == null) &&
                             i.Status != IncidentStatus.Resolved &&
                             i.Status != IncidentStatus.Suppressed, ct);

        var criticalIncidents = await dbContext.OperationalIncidents
            .CountAsync(i => (i.TenantId == tenantId || i.TenantId == null) &&
                             i.Status != IncidentStatus.Resolved &&
                             i.Status != IncidentStatus.Suppressed &&
                             i.Severity == IncidentSeverity.Critical, ct);

        var pendingJobs = await dbContext.SecurityScanJobs
            .CountAsync(j => j.TenantId == tenantId && j.Status == SecurityScanJobStatus.Queued, ct);

        var runningJobs = await dbContext.SecurityScanJobs
            .CountAsync(j => j.TenantId == tenantId && j.Status == SecurityScanJobStatus.Running, ct);

        var overdueCampaigns = await dbContext.ScanCampaigns
            .CountAsync(c => c.TenantId == tenantId && c.Status == CampaignStatus.Active && c.NextRunUtc < now, ct);

        var systemHealth = criticalIncidents > 0 ? "Degraded" : (activeIncidents > 0 ? "Warning" : "Healthy");

        return Ok(new
        {
            systemHealth,
            activeIncidents,
            criticalIncidents,
            pendingJobs,
            runningJobs,
            overdueCampaigns,
            evaluatedAtUtc = now
        });
    }

    [HttpGet("incidents")]
    public async Task<IActionResult> GetIncidents(
        [FromQuery] IncidentStatus? status,
        [FromQuery] IncidentSeverity? severity,
        [FromQuery] IncidentCategory? category,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;
        var query = dbContext.OperationalIncidents
            .Include(i => i.AiDiagnosis)
            .Where(i => i.TenantId == tenantId || i.TenantId == null);

        if (status.HasValue)
        {
            query = query.Where(i => i.Status == status.Value);
        }

        if (severity.HasValue)
        {
            query = query.Where(i => i.Severity == severity.Value);
        }

        if (category.HasValue)
        {
            query = query.Where(i => i.Category == category.Value);
        }

        var totalCount = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(i => i.Severity)
            .ThenByDescending(i => i.LastObservedAtUtc)
            .Skip((Math.Max(1, page) - 1) * Math.Clamp(pageSize, 1, 100))
            .Take(Math.Clamp(pageSize, 1, 100))
            .ToListAsync(ct);

        return Ok(new
        {
            totalCount,
            page,
            pageSize,
            items
        });
    }

    [HttpPost("incidents/{id:guid}/diagnose")]
    public async Task<IActionResult> DiagnoseIncident(Guid id, CancellationToken ct)
    {
        try
        {
            var diagnosis = await aiDiagnosisService.DiagnoseIncidentAsync(id, ct);
            return Ok(diagnosis);
        }
        catch (KeyNotFoundException)
        {
            return NotFound(new { message = $"Incident {id} not found." });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to diagnose incident {IncidentId}", id);
            return StatusCode(500, new { message = "Failed to run AI diagnosis.", error = ex.Message });
        }
    }

    [HttpPost("incidents/{id:guid}/mitigate")]
    public async Task<IActionResult> MitigateIncident(Guid id, [FromBody] MitigateIncidentRequest? request, CancellationToken ct)
    {
        var success = await incidentEngine.ApplyMitigationAsync(id, request?.Notes, ct);
        if (!success)
        {
            return NotFound(new { message = $"Incident {id} not found or could not be mitigated." });
        }

        return Ok(new { success = true, message = "Mitigation applied successfully." });
    }

    [HttpPost("incidents/{id:guid}/resolve")]
    public async Task<IActionResult> ResolveIncident(Guid id, [FromBody] ResolveIncidentRequest request, CancellationToken ct)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Notes))
        {
            return BadRequest(new { message = "Resolution notes are required." });
        }

        var success = await incidentEngine.ResolveIncidentAsync(id, request.Notes, ct);
        if (!success)
        {
            return NotFound(new { message = $"Incident {id} not found." });
        }

        return Ok(new { success = true, message = "Incident resolved." });
    }

    [HttpPost("cycle")]
    public async Task<IActionResult> TriggerDetectionCycle(CancellationToken ct)
    {
        await incidentEngine.RunDetectionCycleAsync(ct);
        return Ok(new { success = true, message = "Detection cycle executed." });
    }
}

public record MitigateIncidentRequest(string? Notes);
public record ResolveIncidentRequest(string Notes);
