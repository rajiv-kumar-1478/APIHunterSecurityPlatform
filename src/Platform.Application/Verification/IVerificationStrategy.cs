using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Verification;

public record VerificationStrategyResult(
    bool Verified,
    string ValidationResultStatus,
    string DetailsJson);

public interface IVerificationStrategy
{
    bool Supports(RemediationActionType actionType);
    Task<VerificationStrategyResult> VerifyAsync(RemediationAction action, CredentialValidationResult? lastValidation, CancellationToken ct = default);
}
