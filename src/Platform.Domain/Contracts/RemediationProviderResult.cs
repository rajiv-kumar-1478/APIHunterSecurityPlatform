namespace Platform.Domain.Contracts;

public sealed record RemediationProviderResult(
    bool Success,
    string? ProviderOperationId,
    string? FailureCode,
    string? FailureReason,
    string ExecutionMetadataJson = "{}");
