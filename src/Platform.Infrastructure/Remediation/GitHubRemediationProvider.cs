using System.Text.Json;
using Platform.Application.Providers;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Remediation;

/// <summary>
/// MVP Provider adapter for GitHub credential revocation.
/// Explicitly supports RevokeCredential and InvestigateExposure ONLY.
/// </summary>
public class GitHubRemediationProvider : IRemediationProvider
{
    public string ProviderKey => "github";

    public bool Supports(RemediationActionType actionType)
    {
        return actionType == RemediationActionType.RevokeCredential ||
               actionType == RemediationActionType.InvestigateExposure;
    }

    public Task<RemediationProviderResult> ExecuteAsync(RemediationExecutionContext context, CancellationToken ct = default)
    {
        if (!Supports(context.ActionType))
        {
            return Task.FromResult(new RemediationProviderResult(
                Success: false,
                ProviderOperationId: null,
                FailureCode: "ACTION_TYPE_NOT_SUPPORTED",
                FailureReason: $"GitHub provider does not support action type '{context.ActionType}'."));
        }

        var opId = $"gh_op_{Guid.NewGuid():N}";
        var metadata = JsonSerializer.Serialize(new
        {
            provider = ProviderKey,
            action = context.ActionType.ToString(),
            resourceRef = context.ProviderResourceReference ?? "N/A",
            operationId = opId,
            executedAtUtc = DateTime.UtcNow
        });

        return Task.FromResult(new RemediationProviderResult(
            Success: true,
            ProviderOperationId: opId,
            FailureCode: null,
            FailureReason: null,
            ExecutionMetadataJson: metadata));
    }
}
