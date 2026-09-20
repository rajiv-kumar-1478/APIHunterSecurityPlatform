using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Observability;
using Platform.Application.Operations;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Operations;

public class IncidentEngineService(
    IPlatformDbContext dbContext,
    ILogger<IncidentEngineService> logger) : IIncidentEngineService
{
    public async Task RunDetectionCycleAsync(CancellationToken ct = default)
    {
        logger.LogDebug("Running autonomous incident detection cycle...");

        var now = DateTime.UtcNow;

        // 1. Detect expired worker leases on SecurityScanJobs
        var staleThreshold = now.AddMinutes(-5);
        var staleScanJobs = await dbContext.SecurityScanJobs
            .Where(j => j.Status == SecurityScanJobStatus.Running &&
                        ((j.LastHeartbeatUtc != null && j.LastHeartbeatUtc < staleThreshold) ||
                         (j.LastHeartbeatUtc == null && j.StartedAtUtc != null && j.StartedAtUtc < staleThreshold)))
            .Take(50)
            .ToListAsync(ct);

        foreach (var job in staleScanJobs)
        {
            var fingerprint = $"stale_worker_lease_{job.WorkerInstanceId ?? "unknown"}_{job.Id}";
            var title = $"Worker lease lost for Scan Job {job.Id} (Worker: {job.WorkerInstanceId ?? "unknown"})";

            logger.LogWarning("Detected stale scan job {JobId} on worker {WorkerId}. Revoking lease.", job.Id, job.WorkerInstanceId);

            // Autonomous self-healing: return job to Queued or TimedOut
            if (job.JobVersion >= 3)
            {
                job.Status = SecurityScanJobStatus.TimedOut;
                job.FailureReason = "Automated lease recovery: job exceeded max retries after worker stall.";
                job.CompletedAtUtc = now;
                PlatformMetrics.JobsTimedOut.Add(1);
            }
            else
            {
                job.Status = SecurityScanJobStatus.Queued;
                job.JobVersion++;
                job.WorkerInstanceId = null;
                job.LastHeartbeatUtc = null;
            }

            var incident = await RecordOrUpdateIncidentAsync(
                title,
                fingerprint,
                IncidentCategory.WorkerHeartbeatLost,
                IncidentSeverity.High,
                job.TenantId,
                detailsJson: $"{{\"jobId\":\"{job.Id}\",\"workerId\":\"{job.WorkerInstanceId}\",\"version\":{job.JobVersion}}}",
                ct: ct);

            incident.MitigationActionTaken = $"Autonomous self-healing: Lease revoked and status set to {job.Status}";
            incident.Status = IncidentStatus.Mitigated;
            PlatformMetrics.IncidentsRecovered.Add(1);
        }

        // 2. Detect campaign stalls (active campaigns overdue by > 15 minutes)
        var campaignStallThreshold = now.AddMinutes(-15);
        var stalledCampaigns = await dbContext.ScanCampaigns
            .Where(c => c.Status == CampaignStatus.Active &&
                        c.NextRunUtc != null &&
                        c.NextRunUtc < campaignStallThreshold)
            .Take(20)
            .ToListAsync(ct);

        foreach (var campaign in stalledCampaigns)
        {
            var fingerprint = $"campaign_stall_{campaign.Id}";
            var title = $"Scan Campaign '{campaign.Name}' is stalled (overdue since {campaign.NextRunUtc:u})";

            logger.LogWarning("Detected stalled campaign {CampaignId} ({Name})", campaign.Id, campaign.Name);

            await RecordOrUpdateIncidentAsync(
                title,
                fingerprint,
                IncidentCategory.CampaignStall,
                IncidentSeverity.Medium,
                campaign.TenantId,
                detailsJson: $"{{\"campaignId\":\"{campaign.Id}\",\"nextRunUtc\":\"{campaign.NextRunUtc:o}\"}}",
                ct: ct);
        }

        // 3. Update telemetry gauges
        var pendingDepth = await dbContext.SecurityScanJobs
            .CountAsync(j => j.Status == SecurityScanJobStatus.Queued, ct);
        PlatformMetrics.SetPendingQueueDepth(pendingDepth);

        var overdueCampaigns = await dbContext.ScanCampaigns
            .CountAsync(c => c.Status == CampaignStatus.Active && c.NextRunUtc < now, ct);
        PlatformMetrics.SetOverdueCampaigns(overdueCampaigns);

        await dbContext.SaveChangesAsync(ct);
    }

    public async Task<OperationalIncident> RecordOrUpdateIncidentAsync(
        string title,
        string fingerprint,
        IncidentCategory category,
        IncidentSeverity severity,
        Guid? tenantId = null,
        string? detailsJson = null,
        CancellationToken ct = default)
    {
        var windowStart = DateTime.UtcNow.AddMinutes(-60);

        var existing = await dbContext.OperationalIncidents
            .FirstOrDefaultAsync(i => i.Fingerprint == fingerprint && i.LastObservedAtUtc >= windowStart, ct);

        if (existing != null)
        {
            existing.OccurrenceCount++;
            existing.LastObservedAtUtc = DateTime.UtcNow;
            if (!string.IsNullOrWhiteSpace(detailsJson))
            {
                existing.DetailsJson = detailsJson;
            }
            if (existing.Status == IncidentStatus.Resolved)
            {
                existing.Status = IncidentStatus.Detected; // Re-open if observed again
            }

            return existing;
        }

        var incident = new OperationalIncident
        {
            TenantId = tenantId,
            Title = title,
            Fingerprint = fingerprint,
            Category = category,
            Severity = severity,
            Status = IncidentStatus.Detected,
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow,
            OccurrenceCount = 1,
            DetailsJson = detailsJson
        };

        dbContext.OperationalIncidents.Add(incident);
        PlatformMetrics.IncidentsDetected.Add(1);

        return incident;
    }

    public async Task<bool> ApplyMitigationAsync(Guid incidentId, string? notes = null, CancellationToken ct = default)
    {
        var incident = await dbContext.OperationalIncidents.FirstOrDefaultAsync(i => i.Id == incidentId, ct);
        if (incident == null) return false;

        using var activity = PlatformTracing.StartIncidentMitigationActivity(incident.Id, incident.Category.ToString());

        switch (incident.Category)
        {
            case IncidentCategory.CampaignStall:
                if (incident.TenantId.HasValue)
                {
                    var stalled = await dbContext.ScanCampaigns
                        .Where(c => c.TenantId == incident.TenantId.Value && c.Status == CampaignStatus.Active)
                        .ToListAsync(ct);

                    foreach (var c in stalled)
                    {
                        c.NextRunUtc = DateTime.UtcNow;
                    }
                }
                break;

            case IncidentCategory.WorkerHeartbeatLost:
            case IncidentCategory.LeaseDeadlock:
                Guid? targetJobId = null;
                if (!string.IsNullOrWhiteSpace(incident.DetailsJson))
                {
                    try
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(incident.DetailsJson);
                        if (doc.RootElement.TryGetProperty("jobId", out var prop) && Guid.TryParse(prop.GetString(), out var parsedJobId))
                        {
                            targetJobId = parsedJobId;
                        }
                    }
                    catch
                    {
                        // Ignore JSON parsing errors
                    }
                }

                var stuckQuery = dbContext.SecurityScanJobs
                    .Where(j => j.Status == SecurityScanJobStatus.Running);

                if (targetJobId.HasValue)
                {
                    stuckQuery = stuckQuery.Where(j => j.Id == targetJobId.Value);
                }
                else if (incident.TenantId.HasValue)
                {
                    var staleCutoff = DateTime.UtcNow.AddMinutes(-5);
                    stuckQuery = stuckQuery.Where(j => j.TenantId == incident.TenantId.Value &&
                                                       (j.LastHeartbeatUtc == null || j.LastHeartbeatUtc < staleCutoff));
                }
                else
                {
                    var staleCutoff = DateTime.UtcNow.AddMinutes(-5);
                    stuckQuery = stuckQuery.Where(j => j.LastHeartbeatUtc == null || j.LastHeartbeatUtc < staleCutoff);
                }

                var stuckJobs = await stuckQuery.ToListAsync(ct);
                foreach (var j in stuckJobs)
                {
                    j.Status = SecurityScanJobStatus.Queued;
                    j.WorkerInstanceId = null;
                    j.LastHeartbeatUtc = null;
                }
                break;
        }

        incident.Status = IncidentStatus.Mitigated;
        incident.MitigationActionTaken = notes ?? "Manual mitigation applied via incident triage";
        PlatformMetrics.IncidentsRecovered.Add(1);

        await dbContext.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> ResolveIncidentAsync(Guid incidentId, string notes, CancellationToken ct = default)
    {
        var incident = await dbContext.OperationalIncidents.FirstOrDefaultAsync(i => i.Id == incidentId, ct);
        if (incident == null) return false;

        incident.Status = IncidentStatus.Resolved;
        incident.ResolutionNotes = notes;

        await dbContext.SaveChangesAsync(ct);
        return true;
    }

    public async Task<List<OperationalIncident>> GetActiveIncidentsAsync(Guid? tenantId = null, CancellationToken ct = default)
    {
        var query = dbContext.OperationalIncidents
            .Include(i => i.AiDiagnosis)
            .Where(i => i.Status != IncidentStatus.Resolved && i.Status != IncidentStatus.Suppressed);

        if (tenantId.HasValue)
        {
            query = query.Where(i => i.TenantId == tenantId.Value || i.TenantId == null);
        }

        return await query.OrderByDescending(i => i.Severity)
                          .ThenByDescending(i => i.LastObservedAtUtc)
                          .Take(100)
                          .ToListAsync(ct);
    }
}
