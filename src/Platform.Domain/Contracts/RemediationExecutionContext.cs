using Platform.Domain.Enums;

namespace Platform.Domain.Contracts;

public sealed record RemediationExecutionContext(
    Guid ActionId,
    Guid FindingId,
    Guid RepositoryId,
    RemediationActionType ActionType,
    string ProviderKey,
    string? ProviderResourceReference,
    int PreExecutionRiskScore,
    ProtectedCredential? ResolvedCredential = null);
