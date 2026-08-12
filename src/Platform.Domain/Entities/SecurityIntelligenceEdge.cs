using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class SecurityIntelligenceEdge
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SourceNodeId { get; set; }
    public Guid TargetNodeId { get; set; }
    public IntelligenceEdgeType EdgeType { get; set; }
    
    // Explicit Provenance Fields
    public DiscoveryType DiscoverySource { get; set; } = DiscoveryType.AiInvestigator;
    public FindingConfidence Confidence { get; set; } = FindingConfidence.High;
    public string EvidenceReference { get; set; } = string.Empty; // e.g. "Investigation #123 (config.py:L40-52)"
    public DateTime FirstObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastObservedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public SecurityIntelligenceNode SourceNode { get; set; } = null!;
    public SecurityIntelligenceNode TargetNode { get; set; } = null!;
}
