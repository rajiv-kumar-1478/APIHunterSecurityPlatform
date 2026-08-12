using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class RepositoryRiskScore
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public int Score { get; set; } // 0 - 100
    public RiskSeverity Severity { get; set; } = RiskSeverity.Low;
    public string AlgorithmVersion { get; set; } = "v1.0"; // Algorithm versioning (e.g. "v1.0")
    public string FactorBreakdownJson { get; set; } = "[]"; // Itemized factor contributions
    public DateTime CalculatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public Repository Repository { get; set; } = null!;
}
