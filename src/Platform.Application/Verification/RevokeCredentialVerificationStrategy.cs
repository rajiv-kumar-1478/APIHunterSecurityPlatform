using System.Text.Json;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Verification;

public class RevokeCredentialVerificationStrategy : IVerificationStrategy
{
    public bool Supports(RemediationActionType actionType)
    {
        return actionType == RemediationActionType.RevokeCredential ||
               actionType == RemediationActionType.InvestigateExposure;
    }

    public Task<VerificationStrategyResult> VerifyAsync(RemediationAction action, CredentialValidationResult? lastValidation, CancellationToken ct = default)
    {
        if (lastValidation == null)
        {
            var json = JsonSerializer.Serialize(new
            {
                strategy = nameof(RevokeCredentialVerificationStrategy),
                actionId = action.Id,
                status = "NO_VALIDATION_RECORD_FOUND",
                reason = "No credential validation record available for verification."
            });
            return Task.FromResult(new VerificationStrategyResult(false, "UNVALIDATED", json));
        }

        bool isVerified = lastValidation.Status == ValidationStatus.Invalid ||
                           lastValidation.Status == ValidationStatus.Expired ||
                           lastValidation.Status == ValidationStatus.Revoked;

        string statusText = lastValidation.Status.ToString();
        var detailsJson = JsonSerializer.Serialize(new
        {
            strategy = nameof(RevokeCredentialVerificationStrategy),
            actionId = action.Id,
            providerKey = action.ProviderKey,
            validationStatus = statusText,
            isRevokedOrInvalid = isVerified,
            verifiedAtUtc = DateTime.UtcNow
        });

        return Task.FromResult(new VerificationStrategyResult(isVerified, statusText, detailsJson));
    }
}
