using System.ComponentModel.DataAnnotations;

namespace Platform.Domain.Entities;

public class AiOperationalDiagnosis
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid IncidentId { get; set; }

    public DateTime AnalyzedAtUtc { get; set; } = DateTime.UtcNow;

    [MaxLength(64)]
    public string ProviderUsed { get; set; } = string.Empty;

    public string RootCauseSummary { get; set; } = string.Empty;

    public string SuggestedRemediation { get; set; } = string.Empty;

    public double ConfidenceScore { get; set; } = 1.0;

    public bool IsDeterministicFallback { get; set; }

    public string SanitizedPrompt { get; set; } = string.Empty;
}
