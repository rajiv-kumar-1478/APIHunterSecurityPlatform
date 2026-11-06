namespace Platform.Application.Contracts;

/// <summary>
/// Declarative validation plan produced by the AI investigator. The destination host is never
/// trusted from the plan; the executor maps it onto a server-controlled allowlisted provider
/// origin before any request is sent.
/// </summary>
public sealed record AiValidationPlan(
    string Method,
    string Url,
    string? AuthType,
    string? AuthHeaderName,
    int? ExpectedStatus,
    string? SuccessJsonPath,
    string? Description);

public interface IAiValidationPlanExecutor
{
    Task<ValidationResultDto> ExecuteAsync(
        string providerName,
        AiValidationPlan plan,
        string decryptedSecret,
        CancellationToken ct = default);
}
