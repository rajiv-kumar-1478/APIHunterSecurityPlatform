using Platform.Application.Providers;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Remediation;

public class SafeFallbackRemediationProvider : IRemediationProvider
{
    public string ProviderKey => "fallback";

    public bool Supports(RemediationActionType actionType) => false;

    public Task<RemediationProviderResult> ExecuteAsync(RemediationExecutionContext context, CancellationToken ct = default)
    {
        return Task.FromResult(new RemediationProviderResult(
            Success: false,
            ProviderOperationId: null,
            FailureCode: "PROVIDER_NOT_SUPPORTED",
            FailureReason: $"No active provider adapter registered for provider key '{context.ProviderKey}'. Execution rejected."));
    }
}
