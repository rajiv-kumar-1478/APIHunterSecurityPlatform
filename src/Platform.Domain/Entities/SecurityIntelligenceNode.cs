using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityIntelligenceNode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public IntelligenceNodeType NodeType { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public Guid? RelatedEntityId { get; set; }
    public string MetadataJson { get; set; } = "{}";
    public DateTime FirstObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<SecurityIntelligenceEdge> OutgoingEdges { get; set; } = new List<SecurityIntelligenceEdge>();
    public ICollection<SecurityIntelligenceEdge> IncomingEdges { get; set; } = new List<SecurityIntelligenceEdge>();
}
