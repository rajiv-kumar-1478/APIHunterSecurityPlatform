namespace Platform.Application.Configuration;

public class ValidationPolicyOptions
{
    public const string SectionName = "ValidationPolicy";

    public bool GlobalEnabled { get; set; } = true;
    public bool DryRun { get; set; } = false;
    public int MaxBatchSize { get; set; } = 50;
    public int MaxDurationSeconds { get; set; } = 15;
    public string PolicyVersion { get; set; } = "1.0.0";
    public string AnthropicValidationModel { get; set; } = "claude-3-haiku-20240307";
}
