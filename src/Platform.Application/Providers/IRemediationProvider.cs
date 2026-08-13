using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Providers;

public interface IRemediationProvider
{
    string ProviderKey { get; }
    bool Supports(RemediationActionType actionType);
    Task<RemediationProviderResult> ExecuteAsync(RemediationExecutionContext context, CancellationToken ct = default);
}
