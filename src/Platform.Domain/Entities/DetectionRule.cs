using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public class DetectionRule
{
    /// <summary>
    /// Rule ID (e.g., "openai-api-key").
    /// Part 1 of composite primary key (Id, Version).
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Version integer.
    /// Part 2 of composite primary key (Id, Version).
    /// Allows historical versions of a rule to coexist in the DB.
    /// </summary>
    public int Version { get; set; } = 1;

    public string Description { get; set; } = string.Empty;
    public string RegexPattern { get; set; } = string.Empty;
    public string CredentialType { get; set; } = string.Empty;
    public string Confidence { get; set; } = "High";
    public string? TagsJson { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? AllowlistPatternsJson { get; set; }
    public RuleSource Source { get; set; } = RuleSource.BuiltIn;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation
    public ICollection<CandidateOccurrence> Occurrences { get; set; } = [];
}
