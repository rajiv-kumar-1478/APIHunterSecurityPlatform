using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RemediationActionHistory
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RemediationActionId { get; set; }

    public RemediationActionStatus? FromStatus { get; set; }
    public RemediationActionStatus ToStatus { get; set; }

    public Guid? ChangedByUserId { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string MetadataJson { get; set; } = "{}";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public RemediationAction RemediationAction { get; set; } = null!;
    public User? ChangedByUser { get; set; }
}
