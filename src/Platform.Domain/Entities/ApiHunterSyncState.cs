using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class ApiHunterSyncState
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public long LastSyncedKeyId { get; set; }
    public DateTime LastSyncStartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastSyncCompletedAtUtc { get; set; }
    public SyncStatus Status { get; set; } = SyncStatus.Idle;
    public int RecordsImported { get; set; }
    public int RecordsUpdated { get; set; }
    public int RecordsSkipped { get; set; }
    public string? ErrorMessage { get; set; }
}
