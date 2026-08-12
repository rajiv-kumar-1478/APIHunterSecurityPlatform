using System.Text.Json;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Permissions;

/// <summary>
/// Service interface for recording audit events.
/// Injected into all application services.
/// </summary>
public interface IAuditService
{
    Task RecordAsync(
        AuditEventCode eventCode,
        Guid? userId,
        Guid? sessionId,
        string ipAddress,
        object? metadata = null,
        CancellationToken ct = default);
}

public class AuditService(
    IPlatformDbContext db,
    ICurrentUserContextProvider correlationProvider,
    ILogger<AuditService> logger) : IAuditService
{
    public async Task RecordAsync(
        AuditEventCode eventCode,
        Guid? userId,
        Guid? sessionId,
        string ipAddress,
        object? metadata = null,
        CancellationToken ct = default)
    {
        try
        {
            var auditEvent = new AuditEvent
            {
                CorrelationId = correlationProvider.CorrelationId,
                UserId = userId,
                SessionId = sessionId,
                EventCode = eventCode,
                IpAddress = ipAddress,
                Metadata = metadata is null ? "{}" : JsonSerializer.Serialize(metadata)
            };

            db.AuditEvents.Add(auditEvent);
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Audit failures must not break the primary operation
            logger.LogError(ex, "Failed to record audit event {EventCode} for user {UserId}", eventCode, userId);
        }
    }
}

public interface ICurrentUserContextProvider
{
    string CorrelationId { get; }
}
