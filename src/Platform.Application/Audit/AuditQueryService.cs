using Platform.Application.Persistence;
using Platform.Domain.Enums;
using Platform.Application.Common;
using Microsoft.EntityFrameworkCore;

namespace Platform.Application.Audit;

public record AuditEventDto(
    Guid Id,
    string CorrelationId,
    Guid? UserId,
    Guid? SessionId,
    string EventCode,
    string ResourceType,
    string ResourceId,
    string IpAddress,
    string Metadata,
    DateTime CreatedAtUtc);

public class AuditQueryService(IPlatformDbContext db)
{
    public async Task<PagedResult<AuditEventDto>> GetAuditEventsAsync(
        PaginationRequest pagination,
        Guid? userId = null,
        AuditEventCode? eventCode = null,
        DateTime? fromUtc = null,
        DateTime? toUtc = null,
        CancellationToken ct = default)
    {
        var query = db.AuditEvents.AsQueryable();

        if (userId.HasValue) query = query.Where(a => a.UserId == userId.Value);
        if (eventCode.HasValue) query = query.Where(a => a.EventCode == eventCode.Value);
        if (fromUtc.HasValue) query = query.Where(a => a.CreatedAtUtc >= fromUtc.Value);
        if (toUtc.HasValue) query = query.Where(a => a.CreatedAtUtc <= toUtc.Value);

        var total = await query.CountAsync(ct);
        var events = await query
            .OrderByDescending(a => a.CreatedAtUtc)
            .Skip(pagination.Skip)
            .Take(pagination.Take)
            .ToListAsync(ct);

        var dtos = events.Select(a => new AuditEventDto(
            a.Id, a.CorrelationId, a.UserId, a.SessionId,
            a.EventCode.ToString(), a.ResourceType, a.ResourceId,
            a.IpAddress, a.Metadata, a.CreatedAtUtc)).ToList();

        return new PagedResult<AuditEventDto>(dtos, total, pagination.Page, pagination.PageSize);
    }
}
