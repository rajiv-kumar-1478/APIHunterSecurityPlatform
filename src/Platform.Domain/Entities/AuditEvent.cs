using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Immutable audit trail. Never update or delete rows.
/// </summary>
public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string CorrelationId { get; set; } = string.Empty;
    public Guid? UserId { get; set; }
    public Guid? SessionId { get; set; }
    public AuditEventCode EventCode { get; set; }
    public string ResourceType { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// JSON metadata. E.g. changed fields, permission codes, provider names.
    /// </summary>
    public string Metadata { get; set; } = "{}";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public User? User { get; set; }
}
