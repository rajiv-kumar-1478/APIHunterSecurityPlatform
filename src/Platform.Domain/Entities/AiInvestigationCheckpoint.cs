using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class AiInvestigationCheckpoint
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid InvestigationJobId { get; set; }
    public AiInvestigationStageType StageType { get; set; }
    public string CursorPosition { get; set; } = string.Empty;
    public string DurableResultJson { get; set; } = "{}";
    public DateTime CompletedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public AiInvestigationJob InvestigationJob { get; set; } = null!;
}
