using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IScannerRuntimeSandbox
{
    Task<ToolExecutionResult> ExecuteInSandboxAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken cancellationToken = default);
}
