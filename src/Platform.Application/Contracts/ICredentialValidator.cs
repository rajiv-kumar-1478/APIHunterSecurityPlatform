using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Contracts;

public record ValidationResultDto(
    ValidationStatus Status,
    ValidationConfidence Confidence,
    string ResponseClassification,
    string SafeEvidenceJson,
    long LatencyMs,
    int? HttpStatusCode = null,
    DateTime? RetryAfterUtc = null);

public interface ICredentialValidator
{
    string ProviderName { get; }
    string ValidatorVersion { get; }
    bool CanValidate(CredentialCandidate candidate);
    Task<ValidationResultDto> ValidateAsync(CredentialCandidate candidate, string decryptedSecret, CancellationToken ct = default);
}
