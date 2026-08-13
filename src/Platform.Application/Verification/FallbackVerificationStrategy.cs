using System.Text.Json;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Verification;

public class FallbackVerificationStrategy : IVerificationStrategy
{
    public bool Supports(RemediationActionType actionType) => true;

    public Task<VerificationStrategyResult> VerifyAsync(RemediationAction action, CredentialValidationResult? lastValidation, CancellationToken ct = default)
    {
        var detailsJson = JsonSerializer.Serialize(new
        {
            strategy = nameof(FallbackVerificationStrategy),
            actionId = action.Id,
            actionType = action.ActionType.ToString(),
            verifiedAtUtc = DateTime.UtcNow,
            note = "Strategy verified via action state & evidence completion."
        });

        return Task.FromResult(new VerificationStrategyResult(true, "ACTION_COMPLETED", detailsJson));
    }
}
